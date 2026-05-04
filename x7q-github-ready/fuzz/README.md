# x7q Fuzzing Scaffold

Fuzzing is not wired into the v0.1 workspace yet. Future work should add a `cargo-fuzz` target that feeds arbitrary byte slices into `x7q_parser::parse` and treats every `Err` as an expected fail-closed outcome.

