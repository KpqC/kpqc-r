library(kpqc)

vector_root <- Sys.getenv("KPQC_TEST_VECTORS", unset = "")
registered_calls <- getDLLRegisteredRoutines(
  getLoadedDLLs()[["kpqc"]]
)$.Call
kat_routine <- registered_calls[["kpqc_kat_set_entropy"]]

if (!nzchar(vector_root)) {
  message("Skipping KATs: KPQC_TEST_VECTORS is not set")
} else {
  if (!dir.exists(vector_root)) {
    stop("KPQC_TEST_VECTORS does not name an existing directory")
  }
  if (is.null(kat_routine)) {
    stop("KPQC_TEST_VECTORS requires a KPQC_TEST_ENTROPY build")
  }

  native_symbol <- function(name) {
    routine <- registered_calls[[name]]
    if (is.null(routine)) {
      stop(sprintf("native test routine %s is not registered", name))
    }
    routine$address
  }

  set_entropy_symbol <- kat_routine$address
  clear_entropy_symbol <- native_symbol("kpqc_kat_clear_entropy")
  drbg_init_symbol <- native_symbol("kpqc_kat_drbg_init")
  drbg_generate_symbol <- native_symbol("kpqc_kat_drbg_generate")
  drbg_clear_symbol <- native_symbol("kpqc_kat_drbg_clear")

  hex_to_raw <- function(value) {
    if (!nzchar(value)) {
      return(raw())
    }
    width <- nchar(value, type = "bytes")
    stopifnot(width %% 2L == 0L)
    starts <- seq.int(1L, width, by = 2L)
    as.raw(strtoi(substring(value, starts, starts + 1L), base = 16L))
  }

  field <- function(vector, name) {
    value <- vector[[name]]
    if (is.null(value)) {
      stop(sprintf("vector %s has no %s field", vector$count, name))
    }
    hex_to_raw(value)
  }

  check_field <- function(algorithm, vector, name, actual) {
    if (!identical(actual, field(vector, name))) {
      stop(sprintf(
        "%s vector %s produced the wrong %s",
        algorithm$id, vector$count, name
      ))
    }
  }

  read_vectors <- function(path, check) {
    lines <- readLines(path, warn = FALSE)
    vector <- list()
    count <- 0L
    flush_vector <- function() {
      if (length(vector) != 0L) {
        check(vector)
        count <<- count + 1L
      }
    }
    for (line in lines) {
      parts <- strsplit(line, " = ", fixed = TRUE)[[1L]]
      if (length(parts) != 2L) {
        next
      }
      if (identical(parts[[1L]], "count") && length(vector) != 0L) {
        flush_vector()
        vector <- list()
      }
      vector[[parts[[1L]]]] <- parts[[2L]]
    }
    flush_vector()
    count
  }

  drbg_init <- function(seed) {
    invisible(.Call(drbg_init_symbol, seed))
  }

  drbg_generate <- function(length) {
    .Call(drbg_generate_symbol, as.integer(length))
  }

  set_entropy <- function(algorithm, entropy) {
    if (!isTRUE(.Call(set_entropy_symbol, algorithm$id, entropy))) {
      stop("could not install deterministic entropy")
    }
  }

  clear_entropy <- function(algorithm) {
    as.integer(.Call(clear_entropy_symbol, algorithm$id))
  }

  with_exact_entropy <- function(algorithm, entropy, operation) {
    set_entropy(algorithm, entropy)
    cleared <- FALSE
    on.exit(if (!cleared) clear_entropy(algorithm), add = TRUE)
    result <- operation()
    remaining <- clear_entropy(algorithm)
    cleared <- TRUE
    if (remaining != 0L) {
      stop(sprintf("deterministic entropy has %d unconsumed bytes", remaining))
    }
    result
  }

  with_repeated_entropy <- function(algorithm, seed, call_bytes, max_calls,
                                    operation) {
    drbg_init(seed)
    chunks <- lapply(seq_len(max_calls), function(index) {
      drbg_generate(call_bytes)
    })
    entropy <- do.call(c, chunks)
    set_entropy(algorithm, entropy)
    cleared <- FALSE
    on.exit(if (!cleared) clear_entropy(algorithm), add = TRUE)
    result <- operation()
    remaining <- clear_entropy(algorithm)
    cleared <- TRUE
    consumed <- length(entropy) - remaining
    if (consumed <= 0L || consumed %% call_bytes != 0L) {
      stop(sprintf(
        "consumed %d deterministic entropy bytes in %d-byte calls",
        consumed, call_bytes
      ))
    }

    drbg_init(seed)
    for (index in seq_len(consumed %/% call_bytes)) {
      drbg_generate(call_bytes)
    }
    result
  }

  signatures <- list(
    list(aimer128f(), "aimer/128f", FALSE, 16L),
    list(aimer128s(), "aimer/128s", FALSE, 16L),
    list(aimer192f(), "aimer/192f", FALSE, 24L),
    list(aimer192s(), "aimer/192s", FALSE, 24L),
    list(aimer256f(), "aimer/256f", FALSE, 32L),
    list(aimer256s(), "aimer/256s", FALSE, 32L),
    list(haetae2(), "haetae/mode2", TRUE, 32L),
    list(haetae3(), "haetae/mode3", TRUE, 32L),
    list(haetae5(), "haetae/mode5", TRUE, 32L)
  )
  kems <- list(
    list(ntruplus768(), "ntruplus/768", 0L, 96L),
    list(ntruplus864(), "ntruplus/864", 0L, 108L),
    list(ntruplus1152(), "ntruplus/1152", 0L, 144L),
    list(smaugt128(), "smaugt/mode1", 2L, 32L),
    list(smaugt192(), "smaugt/mode3", 2L, 32L),
    list(smaugt256(), "smaugt/mode5", 2L, 32L),
    list(timer(), "smaugt/modet", 2L, 16L)
  )

  total <- 0L
  for (config in signatures) {
    algorithm <- config[[1L]]
    path <- config[[2L]]
    is_haetae <- config[[3L]]
    seed_bytes <- config[[4L]]
    count <- read_vectors(file.path(vector_root, path, "kat.rsp"), function(vector) {
      seed <- field(vector, "seed")
      drbg_init(seed)
      if (is_haetae) {
        keys <- with_exact_entropy(
          algorithm,
          drbg_generate(seed_bytes),
          function() generate_key_pair(algorithm)
        )
      } else {
        keys <- with_repeated_entropy(
          algorithm,
          seed,
          seed_bytes,
          128L,
          function() generate_key_pair(algorithm)
        )
      }
      check_field(algorithm, vector, "pk", keys$public_key)
      check_field(algorithm, vector, "sk", keys$secret_key)

      message_value <- field(vector, "msg")
      if (!is.null(vector$sig)) {
        expected_signature <- field(vector, "sig")
      } else {
        signed_message <- field(vector, "sm")
        expected_signature <- signed_message[seq.int(
          length(message_value) + 1L,
          length(signed_message)
        )]
      }

      signing_entropy <- drbg_generate(seed_bytes)
      context <- raw()
      if (is_haetae) {
        context_length <- as.integer(drbg_generate(1L))[[1L]]
        context <- drbg_generate(context_length)
      }
      signature <- with_exact_entropy(
        algorithm,
        signing_entropy,
        function() sign_message(
          algorithm, message_value, keys$secret_key, context
        )
      )
      if (!identical(signature, expected_signature)) {
        stop(sprintf(
          "%s vector %s produced the wrong signature",
          algorithm$id, vector$count
        ))
      }
      stopifnot(verify_signature(
        algorithm, message_value, expected_signature, field(vector, "pk"),
        context
      ))
    })
    stopifnot(count == 100L)
    total <- total + count
  }

  for (config in kems) {
    algorithm <- config[[1L]]
    path <- config[[2L]]
    key_calls <- config[[3L]]
    encapsulation_bytes <- config[[4L]]
    count <- read_vectors(file.path(vector_root, path, "kat.rsp"), function(vector) {
      seed <- field(vector, "seed")
      drbg_init(seed)
      if (key_calls == 0L) {
        keys <- with_repeated_entropy(
          algorithm,
          seed,
          32L,
          128L,
          function() generate_key_pair(algorithm)
        )
      } else {
        key_entropy <- do.call(c, lapply(seq_len(key_calls), function(index) {
          drbg_generate(32L)
        }))
        keys <- with_exact_entropy(
          algorithm,
          key_entropy,
          function() generate_key_pair(algorithm)
        )
      }
      check_field(algorithm, vector, "pk", keys$public_key)
      check_field(algorithm, vector, "sk", keys$secret_key)

      outbound <- with_exact_entropy(
        algorithm,
        drbg_generate(encapsulation_bytes),
        function() encapsulate_secret(algorithm, keys$public_key)
      )
      check_field(algorithm, vector, "ct", outbound$ciphertext)
      check_field(algorithm, vector, "ss", outbound$shared_secret)
      inbound <- decapsulate_secret(
        algorithm, outbound$ciphertext, keys$secret_key
      )
      check_field(algorithm, vector, "ss", inbound)
    })
    stopifnot(count == 100L)
    total <- total + count
  }

  stopifnot(total == 1600L)

  failure_algorithm <- aimer128f()
  set_entropy(failure_algorithm, raw())
  failure <- try(generate_key_pair(failure_algorithm), silent = TRUE)
  stopifnot(inherits(failure, "try-error"))
  stopifnot(clear_entropy(failure_algorithm) == 0L)

  invisible(.Call(drbg_clear_symbol))
  message("Validated all 1,600 KAT records")
}
