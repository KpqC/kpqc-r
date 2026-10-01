library(kpqc)

expect_error <- function(expression) {
  inherits(try(force(expression), silent = TRUE), "try-error")
}

flip_first_byte <- function(value) {
  value[[1L]] <- as.raw(bitwXor(as.integer(value[[1L]]), 1L))
  value
}

filled_raw <- function(length, byte) {
  as.raw(rep.int(as.integer(byte), length))
}

signatures <- signature_algorithms()
kems <- kem_algorithms()

stopifnot(length(signatures) == 9L)
stopifnot(length(kems) == 7L)
stopifnot(all(vapply(signatures, inherits, logical(1), "kpqc_algorithm")))
stopifnot(all(vapply(kems, inherits, logical(1), "kpqc_algorithm")))

message <- charToRaw("release-manifest:v3")
context <- charToRaw("kpqc-r-tests")

for (algorithm in signatures) {
  keys <- generate_key_pair(algorithm)
  stopifnot(length(keys$public_key) == algorithm$sizes[["public_key"]])
  stopifnot(length(keys$secret_key) == algorithm$sizes[["secret_key"]])

  signature <- sign_message(
    algorithm,
    message,
    keys$secret_key,
    context
  )
  stopifnot(length(signature) == algorithm$sizes[["signature"]])
  stopifnot(verify_signature(
    algorithm,
    message,
    signature,
    keys$public_key,
    context
  ))
  stopifnot(!verify_signature(
    algorithm,
    charToRaw("different"),
    signature,
    keys$public_key,
    context
  ))
  stopifnot(!verify_signature(
    algorithm,
    message,
    signature,
    keys$public_key,
    charToRaw("different-context")
  ))
  stopifnot(!verify_signature(
    algorithm,
    message,
    flip_first_byte(signature),
    keys$public_key,
    context
  ))
}

for (algorithm in kems) {
  keys <- generate_key_pair(algorithm)
  stopifnot(length(keys$public_key) == algorithm$sizes[["public_key"]])
  stopifnot(length(keys$secret_key) == algorithm$sizes[["secret_key"]])

  outbound <- encapsulate_secret(algorithm, keys$public_key)
  inbound <- decapsulate_secret(
    algorithm,
    outbound$ciphertext,
    keys$secret_key
  )
  stopifnot(length(outbound$ciphertext) == algorithm$sizes[["ciphertext"]])
  stopifnot(length(outbound$shared_secret) == 32L)
  stopifnot(identical(inbound, outbound$shared_secret))

  if (startsWith(algorithm$id, "NTRU+")) {
    stopifnot(expect_error(encapsulate_secret(
      algorithm,
      filled_raw(algorithm$sizes[["public_key"]], 255L)
    )))
    stopifnot(expect_error(decapsulate_secret(
      algorithm,
      filled_raw(algorithm$sizes[["ciphertext"]], 255L),
      keys$secret_key
    )))
  } else {
    replacement <- decapsulate_secret(
      algorithm,
      flip_first_byte(outbound$ciphertext),
      keys$secret_key
    )
    stopifnot(length(replacement) == algorithm$sizes[["shared_secret"]])
    stopifnot(!identical(replacement, outbound$shared_secret))
  }
}

stopifnot(expect_error(sign_message(ntruplus768(), raw(), raw())))
stopifnot(expect_error(encapsulate_secret(aimer128f(), raw())))
stopifnot(expect_error(generate_key_pair(list(id = "aimer-128f"))))
stopifnot(expect_error(sign_message(aimer128f(), "not raw", raw())))
stopifnot(expect_error(sign_message(
  aimer128f(),
  raw(),
  raw(48),
  raw(256)
)))
