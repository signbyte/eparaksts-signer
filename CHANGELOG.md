# Changelog

Notable changes to this service, newest first, per release. This file is written for whoever
runs the service or integrates against it.

## v0.1.0

Initial code.

The signing service as first released: turns a "sign this document" request into a qualified
electronic signature or seal and returns a standards-compliant signed container. Drives five
signing flows over the eParaksts / Entrust family (local eID card, eID-scan, eParaksts Mobile,
cloud e-seal, CSC remote signing) and produces XAdES, PAdES and ASiC-E signatures at the B-LT
baseline, upgradeable to B-LTA by an archive timestamp. AGPL-3.0-only.
