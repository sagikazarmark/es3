# ES3 Vendor Compatibility Fixture Corpus

This directory is the structured corpus for ES3/XAdES compatibility samples.

The checked-in generated entries cover stable parser, extraction, signature-shape, timestamp-shape, policy-shape, and multi-document profile tests, but they are not vendor output and do not prove Microsec e-Szigno compatibility.

## Layout

- `manifest.tsv` records every checked-in or intentionally blocked corpus entry.
- `generated/` stores local generated fixtures that are not vendor-originated.
- Future `microsec/`, `oracle/`, or third-party directories must only contain lawful public test material with explicit provenance and permission.

## Manifest Fields

Each `manifest.tsv` row records:

- `id`: stable fixture identifier used by tests.
- `path`: path relative to `tests/fixtures`, normally under `vendor/`.
- `subsets`: comma-separated selectors such as `profile`, `extraction`, `document-signature`, `frame-signature`, `timestamp`, `policy`, or `revocation`.
- `source`: origin, vendor/tool, or derivation source.
- `license_or_permission`: license, permission, or why no external permission is needed.
- `generation`: command, generator, or manual construction note.
- `expected_status`: `pass`, `unsupported`, or `blocked-missing-vendor-sample`.
- `sensitive_data`: `none`, `public-test-material`, or `excluded-sensitive`.

Compatibility tests may select fixture subsets by reading `manifest.tsv` and filtering the `subsets` field. The current corpus test validates manifest policy and exercises generated fixtures; broader subset runners can be added as compatibility coverage grows.

## Sensitive Data Policy

Sensitive real-world samples must not be committed.

Do not commit production certificates, private keys, customer data, access tokens, live passwords, or real signed dossiers that contain personal or confidential content. If a lawful sample is useful but sensitive, add only a manifest row with `expected_status=blocked-missing-vendor-sample` or keep the sample outside git and document how an authorized local test can opt in.

Public test material must still be explicitly classified in `manifest.tsv` and documented with source, license or permission, and generation or collection steps.

Top-level XMLDSIG PEM files live outside the vendor corpus. They are generated public test keys and certificates documented in `tests/fixtures/README.md`.
