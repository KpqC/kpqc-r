.new_algorithm <- function(id, type, sizes) {
  structure(
    list(id = id, type = type, sizes = sizes),
    class = c(paste0("kpqc_", type, "_algorithm"), "kpqc_algorithm")
  )
}

.signature_algorithm <- function(id, public_key, secret_key, signature) {
  .new_algorithm(
    id,
    "signature",
    c(public_key = public_key, secret_key = secret_key, signature = signature)
  )
}

.kem_algorithm <- function(id, public_key, secret_key, ciphertext,
                           shared_secret = 32L) {
  .new_algorithm(
    id,
    "kem",
    c(
      public_key = public_key,
      secret_key = secret_key,
      ciphertext = ciphertext,
      shared_secret = shared_secret
    )
  )
}

#' @rdname kpqc_algorithms
#' @export
aimer128f <- function() .signature_algorithm("aimer-128f", 32L, 48L, 6944L)

#' @rdname kpqc_algorithms
#' @export
aimer128s <- function() .signature_algorithm("aimer-128s", 32L, 48L, 4704L)

#' @rdname kpqc_algorithms
#' @export
aimer192f <- function() .signature_algorithm("aimer-192f", 48L, 72L, 15408L)

#' @rdname kpqc_algorithms
#' @export
aimer192s <- function() .signature_algorithm("aimer-192s", 48L, 72L, 10320L)

#' @rdname kpqc_algorithms
#' @export
aimer256f <- function() .signature_algorithm("aimer-256f", 64L, 96L, 31360L)

#' @rdname kpqc_algorithms
#' @export
aimer256s <- function() .signature_algorithm("aimer-256s", 64L, 96L, 20224L)

#' @rdname kpqc_algorithms
#' @export
haetae2 <- function() .signature_algorithm("haetae-mode2", 992L, 1408L, 1474L)

#' @rdname kpqc_algorithms
#' @export
haetae3 <- function() .signature_algorithm("haetae-mode3", 1472L, 2112L, 2349L)

#' @rdname kpqc_algorithms
#' @export
haetae5 <- function() .signature_algorithm("haetae-mode5", 2080L, 2752L, 2948L)

#' @rdname kpqc_algorithms
#' @export
ntruplus768 <- function() .kem_algorithm("NTRU+768", 1152L, 2336L, 1152L)

#' @rdname kpqc_algorithms
#' @export
ntruplus864 <- function() .kem_algorithm("NTRU+864", 1296L, 2624L, 1296L)

#' @rdname kpqc_algorithms
#' @export
ntruplus1152 <- function() .kem_algorithm("NTRU+1152", 1728L, 3488L, 1728L)

#' @rdname kpqc_algorithms
#' @export
smaugt128 <- function() .kem_algorithm("SMAUG-T128", 672L, 832L, 672L)

#' @rdname kpqc_algorithms
#' @export
smaugt192 <- function() .kem_algorithm("SMAUG-T192", 1088L, 1312L, 992L)

#' @rdname kpqc_algorithms
#' @export
smaugt256 <- function() .kem_algorithm("SMAUG-T256", 1440L, 1728L, 1376L)

#' @rdname kpqc_algorithms
#' @export
timer <- function() .kem_algorithm("TiMER", 672L, 832L, 608L)

#' @rdname kpqc_algorithms
#' @export
signature_algorithms <- function() {
  list(
    aimer128f(), aimer128s(), aimer192f(), aimer192s(), aimer256f(),
    aimer256s(), haetae2(), haetae3(), haetae5()
  )
}

#' @rdname kpqc_algorithms
#' @export
kem_algorithms <- function() {
  list(
    ntruplus768(), ntruplus864(), ntruplus1152(), smaugt128(), smaugt192(),
    smaugt256(), timer()
  )
}

#' @export
print.kpqc_algorithm <- function(x, ...) {
  label <- if (identical(x$type, "signature")) "signature" else "KEM"
  cat(sprintf("<kpqc %s algorithm: %s>\n", label, x$id))
  print(x$sizes)
  invisible(x)
}
