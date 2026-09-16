# Contributing to LinUwUx

Thanks for helping improve LinUwUx. Small, focused contributions are easiest
to review and safest to test in a runtime that interposes low-level Wine and
Proton behaviour.

## Before You Start

- Search existing issues before opening a new one.
- Use the [bug-report form](https://github.com/brcly/linuwux-runtime/issues/new?template=bug_report.yml)
  for compatibility problems.
- Discuss substantial features, protocol changes, or behaviour changes in an
  issue before writing the implementation.
- Do not submit game files, proprietary binaries, account details, tokens, or
  unredacted logs.

## Development

Build with the Rust version and host tools listed in the README. Create a branch
from `main`, make one focused change, and keep the unsafe boundary as small and
clear as possible. Prefer descriptive names and simple control flow over source
comments.

Run these checks before opening a pull request:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
cargo xtask build
```

If the change affects runtime behaviour, test it with the relevant Wine or
Proton setup and describe the game, launcher, runner version, and observed
result in the pull request. Changes to component boundaries should also be
checked against the feature combinations exercised by CI.

## Pull Requests

Keep pull requests narrowly scoped and explain the problem, the resulting
behaviour, and the validation performed. Update user-facing documentation when
the installation, configuration, compatibility, or troubleshooting experience
changes.

The project maintainer may request a smaller change, more validation, or a
separate issue before merging.

## License

By submitting a contribution, you agree to license it under the project's
[GNU Affero General Public License, version 3 or later](LICENSE).
