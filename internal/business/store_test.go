package business

import "testing"

func TestDefaultsShowNoMoneyUntilValuesAreEntered(t *testing.T) {
	if Defaults().Loss.Configured() {
		t.Fatal("no dollar figure may appear until the customer enters their values")
	}
	if d := Defaults().FixDays; d.Critical != 7 || d.High != 30 || d.Medium != 90 {
		t.Fatalf("deadlines: %+v", d)
	}
}

func TestSaveValidatesAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	bad := Defaults()
	bad.Loss.LikelihoodHigh = Range{Low: 0.1, High: 1.5}
	if _, err := Save(dir, bad); err == nil {
		t.Fatal("a likelihood above 1 must be refused")
	}
	bad = Defaults()
	bad.Owners["123"] = "x"
	if _, err := Save(dir, bad); err == nil {
		t.Fatal("an owner needs a 12-digit account")
	}
	s := Defaults()
	s.Owners["123456789012"] = "  Platform team "
	s.Owners["210987654321"] = "   "
	s.Loss = Loss{StoreCost: Range{100000, 500000}, LikelihoodHigh: Range{0.05, 0.2}}
	saved, err := Save(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Owners) != 1 || saved.Owners["123456789012"] != "Platform team" || saved.Loss.Currency != "USD" {
		t.Fatalf("blank owners dropped, names trimmed, currency filled: %+v", saved)
	}
	got, _ := Load(dir)
	if !got.Loss.Configured() || got.Owners["123456789012"] != "Platform team" {
		t.Fatalf("reload: %+v", got)
	}
	if NewCache(dir).Owner("123456789012") != "Platform team" || NewCache(dir).Owner("999999999999") != "" {
		t.Fatal("cache lookup")
	}
}
