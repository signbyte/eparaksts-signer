# Contributing

Thank you for considering a contribution. Bug reports, fixes and improvements are welcome. For
anything that could be exploited, use the private route in [SECURITY.md](SECURITY.md) — never a
public issue.

For anything larger than a small fix, please open an issue first and describe what you want to
change and why. This service coordinates a legally meaningful act across several external systems,
so a change that fights its design is better redirected before it is written than after.

## Building and testing

You need the Go toolchain at the version named in [go.mod](go.mod). Every dependency is public, so
nothing needs credentials, a `GOPRIVATE` setting or a vendor directory. The gate a change must pass
is the same one CI runs:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
```

Three more checks run in CI and are worth running before you push:

- **Lint** — `golangci-lint run`, at the version pinned in
  [.github/workflows/ci.yml](.github/workflows/ci.yml); the repo's [.golangci.yml](.golangci.yml)
  carries the configuration.
- **Vulnerabilities** — `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`.
- **The image** — CI builds it, generates an SBOM, fails on HIGH/CRITICAL findings from a
  vulnerability scan, and signs it. A change to the [Dockerfile](Dockerfile) should be built
  locally before you push, because that job is slow to fail.

The committed tree must already be tidy: CI runs `go mod tidy -diff` and fails if it would change
anything, so run `go mod tidy` after touching dependencies. All Go code is `gofmt`-formatted, and
`.gitattributes` pins Go files to LF line endings — leave that alone, it keeps the tidy-diff gate
stable across platforms.

The tests do not need Redis, the packaging service or any external provider: the upstream surfaces
are behind interfaces with test doubles. If a change makes a test need a live external system, that
is a design signal worth raising in the issue rather than solving with a fixture.

## What a change to this service needs

Read the **Security invariants** section of the [README](README.md) before changing anything on the
signing path. They are not documentation of good intentions; each one is the reason a specific
class of defect cannot happen, and a change that weakens one is the change, not a side effect.

The three that carry the most weight:

- **The digest is echoed, never recomputed.** The data to be signed comes back from the digest
  calculation and is passed verbatim to the signer and to finalisation. A person authorises that
  opaque value, so anything that regenerates or adjusts it lets a different document be finalised
  than the one they saw. A change anywhere near it needs a test that fails if the value is
  substituted.
- **One encoding boundary, and it fails hard.** Every flow's signature value is normalised to DER
  in a single place. A value that is neither valid DER nor a recognised fixed-width encoding must
  be rejected — never guessed, never re-encoded on a best effort.
- **At-most-once finalise and archive.** Neither is retried, deliberately, because a second attempt
  can mean a second signature. Retry logic added anywhere near them needs to say why it cannot
  double-sign.

Also load-bearing:

- **Signing and authentication certificates are not interchangeable**, and neither are a person's
  identity and a seal identity. Keep them distinct in names and in types where you can.
- **Nothing sensitive is durable and nothing sensitive is logged**: no document bytes, no signature
  value after finalisation, no upstream token, and no national identifier that has not been
  pseudonymised first.
- **Start-up is fail-closed.** A new configuration knob that a deployment can omit needs a safe
  default or a refusal to start — not a warning.
- **A new signing flow supplies only the variable step.** The spine — session, calculate digest,
  sign, normalise, finalise, deliver — is shared on purpose. A flow that needs its own spine is a
  design discussion first.
- **The validate and archive endpoints relay the upstream report verbatim.** Reshaping it is a
  breaking change for every integrator that parses it.

## Proposing a change

- Work on a branch and open a pull request against `develop`. `develop` is merged into `main` and
  tagged there when a release goes out, so `main` is never committed to directly.
- **Sign off every commit.** This project uses the
  [Developer Certificate of Origin](https://developercertificate.org/): by adding a
  `Signed-off-by: Your Name <you@example.org>` line you certify that you wrote the change or
  otherwise have the right to submit it under this project's licence. `git commit -s` adds the line
  for you; the name and address must match the commit author. A pull request whose commits lack it
  fails the DCO check and cannot be merged.
- Keep the change focused: one concern per pull request.
- A change in behaviour comes with a test that fails without it.
- Match the style around you — naming, error handling, comment density. Comments explain what and
  why in plain domain terms; a reference to a standard is cited in the bracket form already used in
  the code.
- A change that an operator or an integrator can feel — a new or changed endpoint, field, error
  code, configuration knob or default — belongs in [CHANGELOG.md](CHANGELOG.md) in the same pull
  request.
- Pull requests also run a dependency review. A new dependency needs a reason the standard library
  or the existing ones cannot cover.

## Licence

This project is licensed under the **GNU Affero General Public License, version 3 only** (see
[LICENSE](LICENSE)). By submitting a contribution you agree that it is provided under the same
licence.

Worth knowing what AGPL means here, because this is a service rather than a library: if you run a
modified version and let others interact with it over a network, the licence requires you to offer
those users the corresponding source of your modified version. Using it unmodified, or modifying it
for purely internal use with no network users, does not trigger that.
