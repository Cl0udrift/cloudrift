package collectors

import (
	"context"
	"errors"
	"fmt"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func bucketPage(names ...string) []s3types.Bucket {
	out := make([]s3types.Bucket, 0, len(names))
	for _, name := range names {
		out = append(out, s3types.Bucket{Name: awsv2.String(name)})
	}
	return out
}

func TestListBucketPages_SingleAndMultiplePages(t *testing.T) {
	got, err := listBucketPages(context.Background(), func(token *string, pageSize int32) ([]s3types.Bucket, *string, error) {
		if pageSize != listBucketsPageSize {
			t.Fatalf("page size %d", pageSize)
		}
		if token != nil {
			t.Fatal("single page sent a token")
		}
		return bucketPage("only"), nil, nil
	})
	if err != nil || len(got) != 1 {
		t.Fatalf("single page: %d %v", len(got), err)
	}

	var calls int
	got, err = listBucketPages(context.Background(), func(token *string, pageSize int32) ([]s3types.Bucket, *string, error) {
		if pageSize != 1000 {
			t.Fatalf("page size %d", pageSize)
		}
		calls++
		switch calls {
		case 1:
			if token != nil {
				t.Fatal("first token")
			}
			return bucketPage("a"), awsv2.String("t1"), nil
		case 2:
			if token == nil || *token != "t1" {
				t.Fatalf("second token %v", token)
			}
			return bucketPage("b"), nil, nil
		default:
			t.Fatal("extra page")
			return nil, nil, nil
		}
	})
	if err != nil || len(got) != 2 || calls != 2 {
		t.Fatalf("two pages: %d calls %d err %v", len(got), calls, err)
	}

	calls = 0
	got, err = listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		calls++
		if calls < 4 {
			return bucketPage(fmt.Sprintf("p%d", calls)), awsv2.String(fmt.Sprintf("tok-%d", calls)), nil
		}
		return bucketPage("p4"), nil, nil
	})
	if err != nil || len(got) != 4 {
		t.Fatalf("several pages: %d %v", len(got), err)
	}
}

func TestListBucketPages_FullPageEmptyPageAndTokens(t *testing.T) {
	full := make([]s3types.Bucket, listBucketsPageSize)
	for i := range full {
		full[i] = s3types.Bucket{Name: awsv2.String(fmt.Sprintf("b-%d", i))}
	}
	got, err := listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		return full, nil, nil
	})
	if err != nil || len(got) != int(listBucketsPageSize) {
		t.Fatalf("full page: %d %v", len(got), err)
	}

	calls := 0
	got, err = listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		calls++
		if calls == 1 {
			return nil, awsv2.String("after-empty"), nil
		}
		return bucketPage("later"), nil, nil
	})
	if err != nil || len(got) != 1 || calls != 2 {
		t.Fatalf("empty page with token: %d calls %d err %v", len(got), calls, err)
	}

	_, err = listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		return bucketPage("a"), awsv2.String("loop"), nil
	})
	if err == nil {
		t.Fatal("repeated token succeeded")
	}

	calls = 0
	_, err = listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		calls++
		switch calls {
		case 1:
			return bucketPage("a"), awsv2.String("t1"), nil
		case 2:
			return bucketPage("b"), awsv2.String("t2"), nil
		default:
			return bucketPage("c"), awsv2.String("t1"), nil
		}
	})
	if err == nil {
		t.Fatal("reused earlier token succeeded")
	}
}

func TestListBucketPages_ErrorsRetriesCancelAndDuplicates(t *testing.T) {
	_, err := listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		return nil, nil, errors.New("AccessDenied")
	})
	if err == nil {
		t.Fatal("access denied before first page succeeded")
	}

	calls := 0
	_, err = listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		calls++
		if calls == 1 {
			return bucketPage("kept-then-dropped"), awsv2.String("more"), nil
		}
		return nil, nil, errors.New("AccessDenied")
	})
	if err == nil {
		t.Fatal("access denied after a page reported success")
	}

	calls = 0
	got, err := listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		calls++
		if calls == 1 {
			return nil, nil, errors.New("Throttling")
		}
		return bucketPage("after-retry"), nil, nil
	})
	if err != nil || len(got) != 1 || calls != 2 {
		t.Fatalf("throttle retry: %d calls %d err %v", len(got), calls, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	_, err = listBucketPages(ctx, func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		calls++
		cancel()
		return bucketPage("partial"), awsv2.String("next"), nil
	})
	if err == nil {
		t.Fatal("cancellation between pages succeeded")
	}

	got, err = listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		if token == nil {
			return bucketPage("dup", "first"), awsv2.String("n"), nil
		}
		return bucketPage("dup", "second"), nil, nil
	})
	if err != nil || len(got) != 3 {
		t.Fatalf("duplicate bucket: %d %v", len(got), err)
	}

	pages := 25
	got, err = listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		n := 1
		if token != nil {
			fmt.Sscan(*token, &n)
		}
		batch := make([]s3types.Bucket, 40)
		for i := range batch {
			batch[i] = s3types.Bucket{Name: awsv2.String(fmt.Sprintf("bulk-%d-%d", n, i))}
		}
		if n == pages {
			return batch, nil, nil
		}
		return batch, awsv2.String(fmt.Sprintf("%d", n+1)), nil
	})
	if err != nil || len(got) != pages*40 {
		t.Fatalf("large list: %d %v", len(got), err)
	}

	got, err = listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		return nil, nil, nil
	})
	if err != nil || len(got) != 0 {
		t.Fatalf("zero buckets: %d %v", len(got), err)
	}

	left, err := listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		return bucketPage("account-a"), nil, nil
	})
	right, err2 := listBucketPages(context.Background(), func(token *string, _ int32) ([]s3types.Bucket, *string, error) {
		return bucketPage("account-b"), nil, nil
	})
	if err != nil || err2 != nil || len(left) != 1 || len(right) != 1 || awsv2.ToString(left[0].Name) == awsv2.ToString(right[0].Name) {
		t.Fatalf("account isolation: %+v %+v %v %v", left, right, err, err2)
	}
}

func TestNormalizeBucketRegion_IndependentOfClientRegion(t *testing.T) {
	clientRegion := "eu-central-1"
	if got := normalizeBucketRegion(""); got != "us-east-1" {
		t.Fatalf("empty constraint %s", got)
	}
	if got := normalizeBucketRegion(s3types.BucketLocationConstraint("us-west-2")); got != "us-west-2" || got == clientRegion {
		t.Fatalf("bucket region %s followed client %s", got, clientRegion)
	}
}
