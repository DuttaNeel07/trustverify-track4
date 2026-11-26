# Attribution and algorithm status

The application implements the integration and lifecycle controls. It does not implement cryptographic primitives or claim invention of HPKE, ML-KEM, ML-DSA, AEAD, SQLite transactions or event-time watermarking.

| Dependency / specification | Use / status |
|---|---|
| [pqcrypto](https://pypi.org/project/pqcrypto/) 0.4.0 (PQClean implementations) | Grader adapter: ML-KEM-768 encapsulation for `protected_read`, ML-DSA-65 audit signatures. This is the PQ library the judging runtime provides |
| [Track 4 Toolkit](https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit) | Adapter v1 contract, `validate.py` and the public practice events used for evaluation. Not vendored; CI clones it |
| [cryptography](https://github.com/pyca/cryptography), Apache-2.0 OR BSD-3-Clause | `messaging` extra: full-prototype primitives through the bundled OpenSSL backend; see its distribution licenses for bundled components |
| [cryptography HPKE](https://cryptography.io/en/stable/hazmat/primitives/hpke/) | Library-provided hybrid ML-KEM-768/X25519 KEM, HKDF and AES-GCM |
| [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) | Base HPKE specification |
| [Post-quantum HPKE draft](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/) | PQ/hybrid HPKE integration is a draft extension, not itself a finalized FIPS standard |
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | Standardized ML-KEM; selected parameter set ML-KEM-768 |
| [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | Standardized ML-DSA; selected parameter set ML-DSA-65 |
| Python standard library / SQLite | HTTP mock services, transactional persistence, structured JSON, hashing, process management; SQLite is public domain |
| [pytest](https://github.com/pytest-dev/pytest), MIT | Development tests only |
| [ReportLab](https://www.reportlab.com/opensource/), BSD | Two-page PDF generation only |

Pinned dependencies are in `pyproject.toml` and `uv.lock`. No third-party code is vendored. The custom signed-offer application framing is documented openly as an unaudited sandbox protocol, not represented as Noise or Signal. Using standardized algorithms does not imply FIPS validation of this application or its cryptographic module.
