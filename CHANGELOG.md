# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.3.0

### Changed — the CSC flow is two flows, and speaks the CSC API as the provider does

**The `csc` flow is gone; there are two in its place, named for how the person's eID card is read:
`cscEidScan` (a phone reads it, with eID Scan) and `cscEidPlugin` (a card reader, through the provider's
own browser extension).** A request naming `csc` is now refused as an unknown flow (`400`). Nothing
running used it: it answered `501` until a CSC client was configured.

Both flows run the provider's real sequence, rebuilt on the `go-csc` client library and its eParaksts
profile: a **credential registration** that returns a short-term signing credential, then a **signature
authorization bound to the exact digests**, each confirmed by the person in the browser, then `signHash`
with that authorization's token. Before the person confirms, the credential must stay valid for two more
minutes; before finalize, each returned value is verified against the credential's certificate; a refused
`signHash` is not retried. The `signAlgo` sent is an OID chosen from the credential's own key algorithms,
never the signing API's algorithm name. The previous flow could not complete against a CSC-conformant
service.

What an operator and a caller see:

- **`?flow=` is required on `prepare`.** It used to fall back to `csc`; a request without it is now
  `400` with *flow is required*.
- **`TSA_ACCESS_CERT_FLOWS` defaults to `cscEidScan,cscEidPlugin`** (was `csc`), so the deployment's own
  timestamp certificate still covers exactly the CSC signings by default. A deployment that set
  `TSA_ACCESS_CERT_FLOWS=csc` explicitly must rename it; the old name is reported at startup and selects
  nothing.
- `CSC_BASE_URL` may be the provider's full CSC base (ending `/csc/v2`) or the part before it; unset, the
  CSC layer is the TrustedX host's `/trustedx-resources/csc/v2`.
- A CSC `prepare` takes the person's **login authentication certificate** alone (`authCertificate`); it is
  what the timestamp is requested with unless `TSA_ACCESS_CERT_FLOWS` names the flow.
- New failure reasons on a CSC job: the short-term certificate expires too soon to finish, the signature
  authorization is not for these documents, a returned signature does not verify.

```http
POST /api/v1/signatures/prepare?flow=cscEidScan
{ "authCertificate": "MIIE…", "documents": [ … ] }
```

## v0.2.0

### Added — choose whose certificate requests the timestamp, per signing flow

The certificate sent as the finalize `authCertificate` is what the timestamp is requested with.
Until now that was always the signer's own authentication certificate, carried on the request — the
signer is entitled to the timestamp, so it costs the deployment nothing — except on the `csc` flow,
which used a certificate from configuration.

That choice is now configuration, and it applies to any flow:

| variable | default | meaning |
|---|---|---|
| `TSA_ACCESS_CERT` | — | this deployment's own timestamping-access certificate (base64, one line; `_FILE` also read) |
| `TSA_ACCESS_CERT_FLOWS` | `csc` | `all`, or a comma-separated list of flow names |

A flow named in the list finalizes with `TSA_ACCESS_CERT`, so **its timestamps are billed to this
deployment rather than to the signer**. Every other flow uses the signer's own certificate, exactly
as before. The default reproduces the previous behaviour, so an upgrade changes nothing.

This exists because not every signing method can supply a certificate that is entitled to a
timestamp — some methods' authentication certificates carry no timestamping entitlement, and some
issue no authentication certificate at all. Those methods send an empty `authCertificate` and can
only be finalized when the deployment supplies one.

An unrecognized flow name is **reported at startup and otherwise ignored** — it selects nothing.
The log line names the unrecognized entry and the valid flow names.

### Changed — a signing with no certificate to timestamp with is refused, not finalized with the wrong one

Previously an `eid` preparation that carried no `authCertificate` was finalized with the **signing**
certificate instead. The two are not interchangeable: only the authentication certificate is what a
timestamp can be requested with, so the substitution produced a request against the wrong
certificate — which looks correct locally and is refused by a real timestamping service.

Such a signing is now refused **before any call to the provider**, with the reason naming what is
missing and the alternative:

```
err:signing:missingAuthCertificate — no certificate to request the timestamp with (send the
signer's authCertificate, or configure this flow to use the deployment's timestamping-access
certificate)
```

Callers that already send the signer's authentication certificate — which includes the portal on
every card signing — are unaffected.

### Added — every timestamp says whose certificate requested it

A timestamp requested with `TSA_ACCESS_CERT` is billed to this deployment; one requested with the
signer's own certificate is not. Nothing in the validation answer distinguishes the two afterwards,
so the service now records it.

Two counters on the metrics endpoint, kept apart so a refusal can never inflate what the deployment
owes:

| metric | labels |
|---|---|
| `signing_timestamp_requests_total` | `source` (`deployment` \| `signer`), `flow`, `op` (`sign` \| `archive`) |
| `signing_timestamp_refused_total` | `flow`, `op` |

Summing `signing_timestamp_requests_total{source="deployment"}` over a period is what the deployment
paid for.

Each timestamp also logs one line at INFO — `certificate_source`, `flow`, `operation` and the job id
— and, when the deployment's own certificate was used, a truncated SHA-256 **fingerprint** of it, so
a charge stays reconcilable after the deployment rotates to another certificate. The certificate
itself is never logged by this line.

A signing or archive refused for want of any certificate logs at WARN and increments
`signing_timestamp_refused_total`. That is a configuration fault, and nothing else announces it
until someone tries to sign.

### Deprecated — `CSC_AUTH_CERT`

`CSC_AUTH_CERT` is the former spelling of `TSA_ACCESS_CERT` and is read only while the new variable
is unset; startup logs a warning when it is what supplied the certificate. Set `TSA_ACCESS_CERT` to
the same value. It will be removed in a later release.

### Changed — the metrics endpoint no longer offers OpenMetrics

A scraper that asked for the OpenMetrics format by sending `Accept: application/openmetrics-text`
used to be answered in it, with the `# EOF` terminator that format requires. This service now
answers in the Prometheus text format whatever the scraper asks for, and writes no `# EOF`:

```http
GET /metrics
Accept: application/openmetrics-text

200 OK
Content-Type: text/plain; version=0.0.4; charset=utf-8
```

**The metric names, labels and values are unchanged**, so Prometheus — and anything else that
accepts the plain-text exposition format — needs nothing done. Two setups need a look: a scrape
configuration that *requires* the OpenMetrics content type, and a check that reads a missing
`# EOF` as a truncated scrape. Both need their expectation relaxed.

The endpoint itself is unchanged otherwise: still `/metrics` (or `METRICS_PATH`), still enabled by
default, and still answered only for trusted addresses (`METRICS_TRUSTED_IPS`, `127.0.0.1` by
default) — so if nothing scrapes this service, there is nothing to do. The change arrives from the
web framework this service is built on rather than from a change of its own, carried in with the
shared libraries below.

### Fixed — a version tag points at the signed image digest again

Publishing a release re-pointed the version tag by rewrapping the image manifest into a new
manifest list, which gave the tag a **different digest from the one the signature covers** — so
verifying the signature on a version tag failed. The retag is now a plain pull, tag and push, which
keeps the digest and therefore keeps the signature valid. Separately, a release published right
after a merge could race the branch build; the job now waits for the image to be published before
tagging.

**A version tag published before this needs one release re-publish** to be re-pointed at the signed
digest. Verifying the rolling `:develop` or `:latest` tag was never affected.

### Notes

- **The shared libraries moved to their current releases** — `go-platform-kit` v1.11.3,
  `go-authbyte` v0.23.1, `go-eidas-audit` v1.2.5, `go-docgate` v1.0.4, `go-gdpr-audit` v1.1.5 and
  `go-sec-events` v1.2.1, with `go-asice` v1.6.2 arriving indirectly through the document gate. They
  carried the web framework, its HTTP stack and the JOSE library up with them — which is where the
  metrics change above comes from. Nothing else changes for you: no endpoint, field, error or
  setting of this service moved, no configuration needs touching, signing and finalize and the
  evidence events behave exactly as before, and the frozen audit envelope is untouched. Two crossed
  library releases are worth naming, both additions rather than changes: `go-authbyte` v0.23.0 added
  a way to tell a natural person's identity code from an organisation's, and `go-sec-events` v1.2.0
  allows a security event to be emitted from work with no request behind it.

- The move also clears two published advisories in the cryptography library this service depends on;
  a third has no fix available yet and was already present before it, and the vulnerability scanner
  reports nothing this service's own code can reach.

## v0.1.0

Initial code.

The signing service as first released: turns a "sign this document" request into a qualified
electronic signature or seal and returns a standards-compliant signed container. Drives five
signing flows over the eParaksts / Entrust family (local eID card, eID-scan, eParaksts Mobile,
cloud e-seal, CSC remote signing) and produces XAdES, PAdES and ASiC-E signatures at the B-LT
baseline, upgradeable to B-LTA by an archive timestamp. AGPL-3.0-only.
