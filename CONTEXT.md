# ES3 Context

This repository currently contains the parse/extract-only ES3 library, a small shared application helper crate, the CLI, and the web app.

## Language

**ES3**:
The current parse/extract-only dossier domain in this repository. ES3 covers parsing, extracting into memory, and verification reporting for existing dossier files. File IO belongs to applications such as the CLI or web app, not the core `es3` library.
_Avoid_: using ES3 as a synonym for generic XMLSec/XMLDSIG.

**Dossier**:
An ES3 file containing one or more embedded documents plus structural and signature-related metadata.
_Avoid_: package, archive.

**Parsed dossier**:
The internal ES3 representation built after XML parsing and before constructing a final `Dossier`: embedded document entries, payload facts, signature and timestamp counts, transform facts, and structural validation messages. It can represent structurally invalid dossiers so `verify_str` and `verify_structure_str` can report observed errors and warnings before final materialization.
_Avoid_: using XML parsing, structural validation, and final `Dossier` construction as interchangeable steps.

**Dossier document extraction capability**:
The ES3 fact that an embedded dossier document is extractable or not, including the reason when extraction is unavailable. Raw transforms remain dossier metadata, but callers should not have to reconstruct extraction capability from transform details.
_Avoid_: moving file IO into the core `es3` library.

**XMLDSIG**:
XML Signature behavior used by ES3 verification reporting through Bergshamra-backed verification.
_Avoid_: treating XMLDSIG support as broad XMLSec parity.

**Bergshamra-backed verification**:
The current ES3 verification path that delegates XMLDSIG verification to Bergshamra crates while ES3 owns its public reports and policy limits.
_Avoid_: implying trust validation beyond explicit caller-provided pinned-certificate or trusted-anchor checks, revocation validation, timestamp validity, legal validity, decryption, or broad XMLSec compatibility.
