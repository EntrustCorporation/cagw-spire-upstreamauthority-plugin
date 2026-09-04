# Contributing

Thanks for your interest in this plugin.

This project is maintained by Entrust. Contributions are welcome, and the
maintainers make the final decision on what is merged. We may decline changes
that do not fit the direction of the plugin, and we will explain why if that
happens.

## Reporting security issues

**Do not open a public issue for a security vulnerability.** See
[SECURITY.md](./SECURITY.md) for how to report one privately.

## Before you start

For anything beyond a small fix, please open an issue first describing what you
would like to change and why. This lets us confirm the change fits the direction
of the plugin before you spend time on it, and gives us a chance to point out
constraints that are not obvious from the code.

Small changes — typo fixes, documentation corrections, clear bugs — do not need
an issue first. Open a pull request directly.

Issues are triaged on a best-effort basis.

## Developer Certificate of Origin

Contributions to this project are accepted under the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO)
version 1.1. This is a statement that you wrote the contribution, or otherwise
have the right to submit it under this project's licence. There is nothing to
sign separately.

Certify it by adding a `Signed-off-by` line to each commit:

```bash
git commit -s -m "Your commit message"
```

which appends:

```
Signed-off-by: Jane Smith <jane@example.com>
```

The name and email must match the ones on the commit. Amend an existing commit
with `git commit --amend -s`.

## Building and testing

You will need Go — see the `go` directive in [go.mod](./go.mod) for the minimum
version.

```bash
make tools   # once: installs the pinned golangci-lint
make build
make test
```

Before opening a pull request, run the same checks CI runs:

```bash
make ci
```

This covers build, formatting, module tidiness, tests, lint, and a vulnerability
scan. An integration test against a live CA Gateway also exists; it skips unless
the relevant environment variables are set. See the README for details.

## Pull requests

- `make ci` must pass.
- Add tests for new behaviour.
- Keep each pull request focused on one change.
- Write clear commit messages describing what changed and why.
- Update the README if you change configuration or user-facing behaviour.
