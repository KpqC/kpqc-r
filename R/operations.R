.algorithm_id <- function(algorithm, expected_type = NULL,
                          operation = "operation") {
  if (!inherits(algorithm, "kpqc_algorithm") ||
      !is.character(algorithm$id) || length(algorithm$id) != 1L ||
      is.na(algorithm$id)) {
    stop("algorithm must be a KpqC algorithm object", call. = FALSE)
  }
  if (!is.null(expected_type) && !identical(algorithm$type, expected_type)) {
    stop(
      sprintf("%s requires a %s algorithm", operation, expected_type),
      call. = FALSE
    )
  }
  algorithm$id
}

.raw_value <- function(value, label) {
  if (!is.raw(value)) {
    stop(sprintf("%s must be a raw vector", label), call. = FALSE)
  }
  value
}

#' @rdname kpqc_operations
#' @export
generate_key_pair <- function(algorithm) {
  id <- .algorithm_id(algorithm)
  result <- .Call(C_kpqc_keypair, id)
  structure(result, class = c("kpqc_key_pair", "list"))
}

#' @rdname kpqc_operations
#' @export
sign_message <- function(algorithm, message, secret_key, context = raw()) {
  id <- .algorithm_id(algorithm, "signature", "sign_message()")
  .Call(
    C_kpqc_sign,
    id,
    .raw_value(message, "message"),
    .raw_value(secret_key, "secret_key"),
    .raw_value(context, "context")
  )
}

#' @rdname kpqc_operations
#' @export
verify_signature <- function(algorithm, message, signature, public_key,
                             context = raw()) {
  id <- .algorithm_id(algorithm, "signature", "verify_signature()")
  .Call(
    C_kpqc_verify,
    id,
    .raw_value(message, "message"),
    .raw_value(signature, "signature"),
    .raw_value(public_key, "public_key"),
    .raw_value(context, "context")
  )
}

#' @rdname kpqc_operations
#' @export
encapsulate_secret <- function(algorithm, public_key) {
  id <- .algorithm_id(algorithm, "kem", "encapsulate_secret()")
  result <- .Call(
    C_kpqc_encapsulate,
    id,
    .raw_value(public_key, "public_key")
  )
  structure(result, class = c("kpqc_encapsulated_secret", "list"))
}

#' @rdname kpqc_operations
#' @export
decapsulate_secret <- function(algorithm, ciphertext, secret_key) {
  id <- .algorithm_id(algorithm, "kem", "decapsulate_secret()")
  .Call(
    C_kpqc_decapsulate,
    id,
    .raw_value(ciphertext, "ciphertext"),
    .raw_value(secret_key, "secret_key")
  )
}

#' @export
print.kpqc_key_pair <- function(x, ...) {
  cat(sprintf(
    "<kpqc key pair: public key %d bytes, secret key %d bytes>\n",
    length(x$public_key), length(x$secret_key)
  ))
  invisible(x)
}

#' @export
print.kpqc_encapsulated_secret <- function(x, ...) {
  cat(sprintf(
    "<kpqc encapsulation: ciphertext %d bytes, shared secret %d bytes>\n",
    length(x$ciphertext), length(x$shared_secret)
  ))
  invisible(x)
}
