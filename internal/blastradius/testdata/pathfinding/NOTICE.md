# pathfinding.cloud snapshot

`paths.json` holds, for each AWS path, its id, category, required permissions and additional permissions. It is taken from the
[pathfinding.cloud](https://pathfinding.cloud) catalog by Seth Art and Datadog Security Labs,
repository https://github.com/DataDog/pathfinding.cloud, commit `b3f449e50cb7f06a881a4703237d4ce7be627683` (2026-11-16), schema 1.8.1.
That project is licensed under the Apache License 2.0. Only the permission data is copied, not the descriptions or steps.

Used by `pathfinding_benchmark_test.go`, which builds a fixture for each path from this data alone and checks Cloudrift's attack search.

To refresh: fetch `https://pathfinding.cloud/paths.json`, keep the AWS records, and write
`[{"id","cat","required":[...],"additional":[...]}]` (`cat` is the record's `category`; `required` and `additional` are the
`permission` names from `permissions.required` and `permissions.additional`). Update the commit above, then run
`go test ./internal/blastradius -run TestPathfindingBenchmark -v` and review any change in the floor.
