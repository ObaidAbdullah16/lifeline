# Contributing

- Keep Lifeline dependency-free: standard library only (CI enforces it).
- Every check needs: an ID, a weight, a one-line summary for each outcome, a remediation, a test with a fake server, and an entry in docs/checks.md.
- Run `gofmt -l .`, `go vet ./...` and `go test -race ./...` before opening a pull request.
- Be kind in issues you open on other projects: offer the report, do not shame.
