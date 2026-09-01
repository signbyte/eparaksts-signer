# Security policy

This service turns a request into a **qualified electronic signature** — a signature that carries
legal effect for the person or organisation whose credential produced it. It holds no signing key
and performs no raw cryptography: the signature value comes from a qualified signature creation
device, and trust decisions are made inside the packaging and validation service against the EU
trust list. What it owns is everything in between — the job lifecycle, the document spine, upstream
authorisation, and the point where a signature value is normalised before finalisation.

That makes its worst failure a specific one. Not a leaked key, which it does not have, but **a
person authorising one thing and something else being signed**.

Please report security problems privately. Do not open a public issue, pull request or discussion
for anything that could be exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/signbyte/eparaksts-signer/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published, and it gives us one place to discuss and co-ordinate a fix with you.

Please include, as far as you can establish it:

- what the problem is, and what an attacker gains from it;
- the smallest set of steps that reproduces it, and against which version or commit;
- which signing flow it needs, and the configuration it needs, if it only appears under particular
  settings;
- whether you have told anyone else, and whether a disclosure date already binds you.

**Please do not send us real signatures, certificates, national identifiers or upstream tokens.**
A redacted trace, or the shape of the value, explains almost any finding here.

## What happens next

- We acknowledge a report within **five working days**.
- We tell you whether we can reproduce it, and what we think its severity is, as soon as we know.
- We keep you updated while a fix is prepared, and we agree a disclosure date with you. Our default
  is to publish an advisory once a fix is available, and in any case within **90 days** of the
  report — earlier if the problem is already public or being exploited.
- We credit you in the advisory unless you would rather stay anonymous.

There is no bug-bounty programme. We are grateful anyway, and we say so publicly.

## What we consider most serious

**Anything that breaks the link between what a person authorised and what was signed.**

- A digest that is recomputed, substituted or altered anywhere between calculation and
  finalisation. The data to be signed is echoed verbatim on purpose — the person authorises an
  opaque digest, so a service that regenerates it can finalise a different document than the one
  they saw.
- A signature finalised against a different document, session or job than the one the
  authorisation belongs to.
- A signature value accepted that is neither valid DER nor a recognised fixed-width encoding — the
  normalisation boundary must fail hard rather than guess, because a guessed re-encoding is a
  signature nobody authorised in that form.
- The signing and authentication certificates being interchanged, so a signature is produced under
  a certificate the person did not sign with.
- A seal identity used where a person's identity was intended, or the reverse. The two carry
  different legal meaning and are selected at different points in the flow.
- Finalising or archive-timestamping more than once for the same job. These are at-most-once by
  design specifically to avoid double-signing; a retry path that defeats that is a serious finding.

**Authorisation and job isolation.**

- Reaching a signing endpoint without a valid, DPoP-bound service token, with a token bound to a
  different key, or with a scope the endpoint does not require.
- The browser callback accepting a replayed or forged `state`, a missing or unverified PKCE
  verifier, or a callback that can be pointed at another job.
- Resuming, reading, mutating or deleting a job that belongs to another caller or tenant. Any
  replica can resume any job from the shared store, which is what makes this boundary load-bearing.

**What must never leak or persist.**

- Document bytes or a signature value surviving finalisation, or reaching durable storage at all.
- An upstream token — for the packaging service, the eID platform or a remote-signing provider —
  reaching a log line, an error body, a response, or a job it was not scoped to.
- A national identifier appearing anywhere unpseudonymised: a log line, an audit record, an error.

**Two quieter ones that still matter.**

- The validation and archive-timestamp endpoints altering the upstream report they relay. They are
  a deliberate verbatim relay; a reshaped verdict misleads every integrator that parses it.
- Starting successfully on missing or invalid configuration. Start-up is fail-closed on purpose,
  and a configuration hole that boots anyway is how a weakened deployment reaches production
  unnoticed.

Denial of service and findings that need an already-compromised host or an already-authenticated
administrator are in scope but lower priority. Reports about outdated dependencies are welcome
where you can show the vulnerable path is actually reachable.

## What is deliberately not a finding

This service **makes no trust decision**. Certificate chains, revocation and timestamp validity are
evaluated by the packaging and validation service against the EU trust list; that a bad certificate
was accepted is not a defect here unless this service mishandled the answer it was given. It also
performs **no raw cryptographic signing** — the value comes from the signature creation device.

A report that an API *implies* either of those guarantees, or that a caller is likely to read it
that way, is a real finding. A report that this service failed to catch what a validator is
responsible for catching is not.

## Scope

This policy covers the code in this repository. It does not cover the external packaging and
validation service, the eID platform surfaces, a remote-signing provider, the qualified signature
creation devices, the trust list, or any deployment operated by someone other than us — report
those to the parties that run them. How a deployment configures this service is the operator's
responsibility, but a report that a **default** is unsafe is very much in scope.

## Supported versions

Security fixes land on the most recent release. Older tags are not patched; if you are pinned to
one, the fix is to move forward.
