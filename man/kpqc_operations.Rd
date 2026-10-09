\name{kpqc_operations}
\alias{generate_key_pair}
\alias{sign_message}
\alias{verify_signature}
\alias{encapsulate_secret}
\alias{decapsulate_secret}
\title{KpqC Cryptographic Operations}
\usage{
generate_key_pair(algorithm)

sign_message(algorithm, message, secret_key, context = raw())

verify_signature(
  algorithm,
  message,
  signature,
  public_key,
  context = raw()
)

encapsulate_secret(algorithm, public_key)

decapsulate_secret(algorithm, ciphertext, secret_key)
}
\arguments{
  \item{algorithm}{A KpqC algorithm object returned by an accessor.}
  \item{message}{A raw vector containing the message.}
  \item{secret_key}{A raw vector containing the secret key.}
  \item{context}{An optional raw vector of at most 255 bytes.}
  \item{signature}{A raw vector containing a detached signature.}
  \item{public_key}{A raw vector containing the public key.}
  \item{ciphertext}{A raw vector containing a KEM ciphertext.}
}
\description{
Generate key pairs, create and verify detached signatures, and establish
shared secrets using a key encapsulation mechanism (KEM).
}
\value{
\code{generate_key_pair()} returns a list with \code{public_key} and
\code{secret_key}. \code{sign_message()} returns a signature raw vector and
\code{verify_signature()} returns one logical value.
\code{encapsulate_secret()} returns a list with \code{ciphertext} and
\code{shared_secret}; \code{decapsulate_secret()} returns a shared-secret raw
vector.
}
\examples{
algorithm <- aimer128f()
keys <- generate_key_pair(algorithm)
message <- charToRaw("hello")
signature <- sign_message(algorithm, message, keys$secret_key)
verify_signature(algorithm, message, signature, keys$public_key)

kem <- ntruplus768()
recipient <- generate_key_pair(kem)
outbound <- encapsulate_secret(kem, recipient$public_key)
inbound <- decapsulate_secret(kem, outbound$ciphertext, recipient$secret_key)
stopifnot(identical(inbound, outbound$shared_secret))
}
