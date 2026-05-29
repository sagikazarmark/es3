# es3

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/sagikazarmark/es3/ci.yaml?style=flat-square)](https://github.com/sagikazarmark/es3/actions/workflows/ci.yaml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sagikazarmark/es3/badge?style=flat-square)](https://securityscorecards.dev/viewer/?uri=github.com/sagikazarmark/es3)
[![crates.io](https://img.shields.io/crates/v/es3?style=flat-square)](https://crates.io/crates/es3)
[![docs.rs](https://img.shields.io/docsrs/es3?style=flat-square)](https://docs.rs/es3)

**ES3 dossier tools for Rust.**

## Features

- **Typed ES3 dossier parsing** from existing dossier XML.
- **Embedded document inspection** with title, MIME type, size, transforms, signatures, timestamps, and extraction capability.
- **Document extraction** for supported payload transforms through the library, CLI, and app.
- **Verification reporting** for dossier structure and XMLDSIG signatures through Bergshamra-backed verification.
- **Explicit trust inputs** for pinned-certificate and trusted-anchor checks when callers provide them.

## Install

Install the command line interface from crates.io:

```bash
cargo install es3-cli
```

The installed binary is named `es3`.

## Command Line

List embedded dossier documents:

```bash
es3 list dossier.es3
```

Extract all extractable embedded documents:

```bash
es3 extract dossier.es3 --output extracted
```

Extract a single embedded document by zero-based index or exact title:

```bash
es3 extract dossier.es3 --output extracted --index 0
es3 extract dossier.es3 --output extracted --title "document.pdf"
```

Verify dossier structure and signatures:

```bash
es3 verify dossier.es3
```

## Library

This repository currently provides the `es3` crate as the parse/extract-only core library.

It exposes typed dossier documents, extraction capability, extraction results, structural reports,
and verification reports. File IO belongs to applications such as the CLI or web app.

## Web App

The `es3-web` crate contains the Dioxus browser app. It shares the same core `es3` parsing and extraction model as the CLI.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
