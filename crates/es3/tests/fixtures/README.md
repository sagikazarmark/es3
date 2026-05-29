# ES3 Test Fixtures

This directory contains only test material.

- `vendor/` is governed by `vendor/manifest.tsv` and `vendor/README.md`.
- `xmldsig-test-private-key.pem`, `xmldsig-test-public-key.pem`, `xmldsig-test-certificate.pem`, and `xmldsig-other-certificate.pem` are generated public test cryptographic material used by signature verification tests. They are intentionally committed and must never be reused for real signatures, credentials, or production trust.
