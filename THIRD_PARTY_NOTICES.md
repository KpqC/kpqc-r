# Third-party notices

This package includes code from the following upstream reference
implementations:

- [AIMer](https://github.com/samsungsds-opensource/AIMer/tree/734cc76fa4695ca8c8eaa070508db8ff62205e68), Copyright (c) 2022–2026 SAMSUNG SDS
- [HAETAE](https://github.com/CryptoLabInc/HAETAE/tree/743c31df48183fc8c8a39a4f50a634da1c4af03a), Copyright (c) 2026 Team HAETAE
- [NTRU+](https://github.com/ntruplus/ntruplus/tree/3991b2ae08d6f0008d37e41b8aceaaab27b4ec89), Copyright (c) 2024–2026 NTRU+ TEAM
- [SMAUG-T](https://github.com/CryptoLabInc/SMAUG-T/tree/bbc463cd788eae36c6d155cef667ac9dbd9054cd), Copyright (c) 2026 Team SMAUG-T
- [BearSSL AES implementation](https://bearssl.org/), used only by the test-only known-answer-test harness, Copyright (c) 2016 Thomas Pornin

These components are distributed under the MIT License. Their original license
texts are included in their source headers or under `src/third_party/`.

## Local integration changes

The bundled sources use the package's operating-system entropy adapter and
propagate entropy failures to the R interface. AIMer's SHAKE contexts use
fixed-size storage instead of terminating the process when allocation fails.
The test-only AES contexts likewise use fixed-size storage and clear expanded
keys when released.

The SMAUG-T sources use unsigned intermediate arithmetic in
`src/third_party/SMAUG-T/src/dg.c`,
`src/third_party/SMAUG-T/src/indcpa.c`, and
`src/third_party/SMAUG-T/src/poly.c` to preserve the reference implementation's
16-bit results without relying on undefined signed left shifts. Minor unused
code and compiler warnings are also cleaned up without changing algorithm
outputs.

All 16 supported parameter sets are validated byte-for-byte against the
referenced known-answer test vectors.
