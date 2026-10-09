# KpqC

KpqC provides synchronous R APIs for the AIMer and HAETAE signature schemes
and the NTRU+ and SMAUG-T key encapsulation mechanisms (KEMs).

## Runtime support

- R 3.6 or newer
- A C11 compiler when installing from source
- Windows, macOS, or Linux

## Install

From GitHub:

```r
install.packages("remotes")
remotes::install_github("KpqC/kpqc-r@v0.1.0")
```

From a source checkout:

```sh
R CMD INSTALL .
```

After a CRAN release:

```r
install.packages("kpqc")
```

## Available schemes

| Algorithm | Type | Accessors |
| --- | --- | --- |
| **AIMer** | Signature | `aimer128f()`, `aimer128s()`, `aimer192f()`, `aimer192s()`, `aimer256f()`, `aimer256s()` |
| **HAETAE** | Signature | `haetae2()`, `haetae3()`, `haetae5()` |
| **NTRU+** | KEM | `ntruplus768()`, `ntruplus864()`, `ntruplus1152()` |
| **SMAUG&#8209;T** | KEM | `smaugt128()`, `smaugt192()`, `smaugt256()`, `timer()` |

### Parameter sizes

Signature sizes are shown in bytes.

| Scheme | Public key | Secret key | Signature |
| --- | ---: | ---: | ---: |
| AIMer-128f | 32 | 48 | 6,944 |
| AIMer-128s | 32 | 48 | 4,704 |
| AIMer-192f | 48 | 72 | 15,408 |
| AIMer-192s | 48 | 72 | 10,320 |
| AIMer-256f | 64 | 96 | 31,360 |
| AIMer-256s | 64 | 96 | 20,224 |
| HAETAE-2 | 992 | 1,408 | 1,474 |
| HAETAE-3 | 1,472 | 2,112 | 2,349 |
| HAETAE-5 | 2,080 | 2,752 | 2,948 |

KEM sizes are shown in bytes.

| Scheme | Public key | Secret key | Ciphertext | Shared secret |
| --- | ---: | ---: | ---: | ---: |
| NTRU+ 768 | 1,152 | 2,336 | 1,152 | 32 |
| NTRU+ 864 | 1,296 | 2,624 | 1,296 | 32 |
| NTRU+ 1152 | 1,728 | 3,488 | 1,728 | 32 |
| SMAUG-T 128 | 672 | 832 | 672 | 32 |
| SMAUG-T 192 | 1,088 | 1,312 | 992 | 32 |
| SMAUG-T 256 | 1,440 | 1,728 | 1,376 | 32 |
| TiMER | 672 | 832 | 608 | 32 |

### Signatures

```r
library(kpqc)

algorithm <- aimer128f()
keys <- generate_key_pair(algorithm)
message <- charToRaw("release-manifest:v3")

signature <- sign_message(algorithm, message, keys$secret_key)
valid <- verify_signature(algorithm, message, signature, keys$public_key)

stopifnot(valid)
```

`sign_message()` and `verify_signature()` accept an optional raw `context`
of at most 255 bytes. Verification fails when the supplied context does not
match the one used for signing.

### KEM

A KEM creates a shared secret for a sender and a recipient. The public key may
be distributed; the secret key and resulting shared secret must remain private.

```r
algorithm <- smaugt192()
recipient <- generate_key_pair(algorithm)
outbound <- encapsulate_secret(algorithm, recipient$public_key)

inbound_secret <- decapsulate_secret(
  algorithm,
  outbound$ciphertext,
  recipient$secret_key
)

stopifnot(identical(inbound_secret, outbound$shared_secret))
```

## Data and failures

Keys, signatures, ciphertexts, messages, contexts, and shared secrets are raw
vectors. Fixed-size inputs are checked before native code is called. Invalid
signatures return `FALSE`; invalid sizes, unsupported operations, and native
failures raise R errors.

NTRU+ rejects non-canonical public keys and invalid ciphertexts with an error.
SMAUG-T uses implicit rejection: an invalid ciphertext returns a replacement
shared secret rather than the sender's shared secret.

The native algorithm sources are included under `src/third_party/` and compile
with the package. Installation does not download native libraries.

## Security

The native cores are compiled from the upstream algorithm implementations.
This package has not received an independent security audit and does not
provide a constant-time execution guarantee. Assess those constraints before
using it with sensitive production keys.

Third-party licenses and attributions are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Known-answer tests

The test suite validates 100 vectors for each of the 16 parameter sets (1,600
vectors total) from
[KpqC/kpqc-test-vectors at commit d75490bf824f](https://github.com/KpqC/kpqc-test-vectors/tree/d75490bf824faa4b148cd0b901a2eb13198fe0da).

```sh
R CMD build .
KPQC_CPPFLAGS=-DKPQC_TEST_ENTROPY \
  KPQC_TEST_VECTORS="$(pwd)/../kpqc-test-vectors" \
  R CMD check --no-manual kpqc_0.1.0.tar.gz
```

The deterministic entropy interface used by these tests is excluded from
normal package builds.
