/* SPDX-License-Identifier: MIT */
#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef int (*keypair_function)(uint8_t *, uint8_t *);
typedef int (*sign_function)(uint8_t *, uint64_t *, const uint8_t *, size_t,
                             const uint8_t *, size_t, const uint8_t *);
typedef int (*verify_function)(const uint8_t *, size_t, const uint8_t *, size_t,
                               const uint8_t *, size_t, const uint8_t *);
typedef int (*encapsulate_function)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*decapsulate_function)(uint8_t *, const uint8_t *,
                                    const uint8_t *);

typedef struct {
    const char *id;
    size_t public_key_size;
    size_t secret_key_size;
    size_t signature_size;
    keypair_function keypair;
    sign_function sign;
    verify_function verify;
} signature_algorithm;

typedef struct {
    const char *id;
    size_t public_key_size;
    size_t secret_key_size;
    size_t ciphertext_size;
    size_t shared_secret_size;
    keypair_function keypair;
    encapsulate_function encapsulate;
    decapsulate_function decapsulate;
} kem_algorithm;

#define DECLARE_SIGNATURE(name)                                                \
    int kpqc_##name##_keypair(uint8_t *, uint8_t *);                           \
    int kpqc_##name##_sign(uint8_t *, uint64_t *, const uint8_t *, size_t,     \
                           const uint8_t *, size_t, const uint8_t *);           \
    int kpqc_##name##_verify(const uint8_t *, size_t, const uint8_t *, size_t, \
                             const uint8_t *, size_t, const uint8_t *)

#define DECLARE_KEM(name)                                                      \
    int kpqc_##name##_keypair(uint8_t *, uint8_t *);                           \
    int kpqc_##name##_encapsulate(uint8_t *, uint8_t *, const uint8_t *);      \
    int kpqc_##name##_decapsulate(uint8_t *, const uint8_t *, const uint8_t *)

DECLARE_SIGNATURE(aimer128f);
DECLARE_SIGNATURE(aimer128s);
DECLARE_SIGNATURE(aimer192f);
DECLARE_SIGNATURE(aimer192s);
DECLARE_SIGNATURE(aimer256f);
DECLARE_SIGNATURE(aimer256s);
DECLARE_SIGNATURE(haetae2);
DECLARE_SIGNATURE(haetae3);
DECLARE_SIGNATURE(haetae5);
DECLARE_KEM(ntruplus768);
DECLARE_KEM(ntruplus864);
DECLARE_KEM(ntruplus1152);
DECLARE_KEM(smaugt128);
DECLARE_KEM(smaugt192);
DECLARE_KEM(smaugt256);
DECLARE_KEM(timer);

#if defined(KPQC_TEST_ENTROPY)
#define DECLARE_TEST_ENTROPY(name)                                             \
    int kpqc_##name##_set_test_entropy(const uint8_t *, size_t);               \
    size_t kpqc_##name##_test_entropy_remaining(void);                         \
    void kpqc_##name##_clear_test_entropy(void)

DECLARE_TEST_ENTROPY(aimer128f);
DECLARE_TEST_ENTROPY(aimer128s);
DECLARE_TEST_ENTROPY(aimer192f);
DECLARE_TEST_ENTROPY(aimer192s);
DECLARE_TEST_ENTROPY(aimer256f);
DECLARE_TEST_ENTROPY(aimer256s);
DECLARE_TEST_ENTROPY(haetae2);
DECLARE_TEST_ENTROPY(haetae3);
DECLARE_TEST_ENTROPY(haetae5);
DECLARE_TEST_ENTROPY(ntruplus768);
DECLARE_TEST_ENTROPY(ntruplus864);
DECLARE_TEST_ENTROPY(ntruplus1152);
DECLARE_TEST_ENTROPY(smaugt128);
DECLARE_TEST_ENTROPY(smaugt192);
DECLARE_TEST_ENTROPY(smaugt256);
DECLARE_TEST_ENTROPY(timer);
#endif

#define SIGNATURE_ENTRY(id_value, name, public_size, secret_size, sig_size)    \
    {id_value, public_size, secret_size, sig_size, kpqc_##name##_keypair,      \
     kpqc_##name##_sign, kpqc_##name##_verify}

#define KEM_ENTRY(id_value, name, public_size, secret_size, cipher_size)       \
    {id_value, public_size, secret_size, cipher_size, 32,                      \
     kpqc_##name##_keypair, kpqc_##name##_encapsulate,                        \
     kpqc_##name##_decapsulate}

static const signature_algorithm signature_algorithms[] = {
    SIGNATURE_ENTRY("aimer-128f", aimer128f, 32, 48, 6944),
    SIGNATURE_ENTRY("aimer-128s", aimer128s, 32, 48, 4704),
    SIGNATURE_ENTRY("aimer-192f", aimer192f, 48, 72, 15408),
    SIGNATURE_ENTRY("aimer-192s", aimer192s, 48, 72, 10320),
    SIGNATURE_ENTRY("aimer-256f", aimer256f, 64, 96, 31360),
    SIGNATURE_ENTRY("aimer-256s", aimer256s, 64, 96, 20224),
    SIGNATURE_ENTRY("haetae-mode2", haetae2, 992, 1408, 1474),
    SIGNATURE_ENTRY("haetae-mode3", haetae3, 1472, 2112, 2349),
    SIGNATURE_ENTRY("haetae-mode5", haetae5, 2080, 2752, 2948),
};

static const kem_algorithm kem_algorithms[] = {
    KEM_ENTRY("NTRU+768", ntruplus768, 1152, 2336, 1152),
    KEM_ENTRY("NTRU+864", ntruplus864, 1296, 2624, 1296),
    KEM_ENTRY("NTRU+1152", ntruplus1152, 1728, 3488, 1728),
    KEM_ENTRY("SMAUG-T128", smaugt128, 672, 832, 672),
    KEM_ENTRY("SMAUG-T192", smaugt192, 1088, 1312, 992),
    KEM_ENTRY("SMAUG-T256", smaugt256, 1440, 1728, 1376),
    KEM_ENTRY("TiMER", timer, 672, 832, 608),
};

#if defined(KPQC_TEST_ENTROPY)
typedef int (*set_test_entropy_function)(const uint8_t *, size_t);
typedef size_t (*test_entropy_remaining_function)(void);
typedef void (*clear_test_entropy_function)(void);

typedef struct {
    const char *id;
    set_test_entropy_function set;
    test_entropy_remaining_function remaining;
    clear_test_entropy_function clear;
} test_entropy_control;

#define TEST_ENTROPY_ENTRY(id_value, name)                                    \
    {id_value, kpqc_##name##_set_test_entropy,                                \
     kpqc_##name##_test_entropy_remaining,                                    \
     kpqc_##name##_clear_test_entropy}

static const test_entropy_control test_entropy_controls[] = {
    TEST_ENTROPY_ENTRY("aimer-128f", aimer128f),
    TEST_ENTROPY_ENTRY("aimer-128s", aimer128s),
    TEST_ENTROPY_ENTRY("aimer-192f", aimer192f),
    TEST_ENTROPY_ENTRY("aimer-192s", aimer192s),
    TEST_ENTROPY_ENTRY("aimer-256f", aimer256f),
    TEST_ENTROPY_ENTRY("aimer-256s", aimer256s),
    TEST_ENTROPY_ENTRY("haetae-mode2", haetae2),
    TEST_ENTROPY_ENTRY("haetae-mode3", haetae3),
    TEST_ENTROPY_ENTRY("haetae-mode5", haetae5),
    TEST_ENTROPY_ENTRY("NTRU+768", ntruplus768),
    TEST_ENTROPY_ENTRY("NTRU+864", ntruplus864),
    TEST_ENTROPY_ENTRY("NTRU+1152", ntruplus1152),
    TEST_ENTROPY_ENTRY("SMAUG-T128", smaugt128),
    TEST_ENTROPY_ENTRY("SMAUG-T192", smaugt192),
    TEST_ENTROPY_ENTRY("SMAUG-T256", smaugt256),
    TEST_ENTROPY_ENTRY("TiMER", timer),
};
#endif

static uint8_t zero_byte;

static const char *algorithm_id(SEXP value) {
    if (TYPEOF(value) != STRSXP || XLENGTH(value) != 1 ||
        STRING_ELT(value, 0) == NA_STRING) {
        Rf_error("algorithm id must be one non-missing string");
    }
    return CHAR(STRING_ELT(value, 0));
}

static const signature_algorithm *find_signature(const char *id) {
    size_t count = sizeof(signature_algorithms) / sizeof(signature_algorithms[0]);
    for (size_t index = 0; index < count; ++index) {
        if (strcmp(signature_algorithms[index].id, id) == 0) {
            return &signature_algorithms[index];
        }
    }
    return NULL;
}

static const kem_algorithm *find_kem(const char *id) {
    size_t count = sizeof(kem_algorithms) / sizeof(kem_algorithms[0]);
    for (size_t index = 0; index < count; ++index) {
        if (strcmp(kem_algorithms[index].id, id) == 0) {
            return &kem_algorithms[index];
        }
    }
    return NULL;
}

#if defined(KPQC_TEST_ENTROPY)
static const test_entropy_control *find_test_entropy_control(const char *id) {
    size_t count = sizeof(test_entropy_controls) /
                   sizeof(test_entropy_controls[0]);
    for (size_t index = 0; index < count; ++index) {
        if (strcmp(test_entropy_controls[index].id, id) == 0) {
            return &test_entropy_controls[index];
        }
    }
    return NULL;
}
#endif

static size_t raw_size(SEXP value, const char *label) {
    if (TYPEOF(value) != RAWSXP) {
        Rf_error("%s must be a raw vector", label);
    }
    R_xlen_t length = XLENGTH(value);
    if (length < 0 || (uintmax_t)length > (uintmax_t)SIZE_MAX) {
        Rf_error("%s is too large", label);
    }
    return (size_t)length;
}

static const uint8_t *raw_input(SEXP value) {
    return XLENGTH(value) == 0 ? &zero_byte : (const uint8_t *)RAW(value);
}

static void require_size(SEXP value, size_t expected, const char *label) {
    size_t actual = raw_size(value, label);
    if (actual != expected) {
        Rf_error("%s must be %zu bytes (received %zu)", label, expected, actual);
    }
}

static void secure_zero(void *value, size_t length) {
    volatile uint8_t *bytes = (volatile uint8_t *)value;
    while (length-- != 0) *bytes++ = 0;
}

static SEXP named_pair(SEXP first, const char *first_name, SEXP second,
                       const char *second_name) {
    SEXP result = PROTECT(Rf_allocVector(VECSXP, 2));
    SEXP names = PROTECT(Rf_allocVector(STRSXP, 2));
    SET_VECTOR_ELT(result, 0, first);
    SET_VECTOR_ELT(result, 1, second);
    SET_STRING_ELT(names, 0, Rf_mkChar(first_name));
    SET_STRING_ELT(names, 1, Rf_mkChar(second_name));
    Rf_setAttrib(result, R_NamesSymbol, names);
    UNPROTECT(2);
    return result;
}

SEXP kpqc_keypair(SEXP algorithm_value) {
    const char *id = algorithm_id(algorithm_value);
    const signature_algorithm *signature = find_signature(id);
    const kem_algorithm *kem = find_kem(id);
    if (signature == NULL && kem == NULL) {
        Rf_error("unknown KpqC algorithm: %s", id);
    }

    size_t public_size = signature != NULL ? signature->public_key_size
                                           : kem->public_key_size;
    size_t secret_size = signature != NULL ? signature->secret_key_size
                                           : kem->secret_key_size;
    keypair_function keypair = signature != NULL ? signature->keypair
                                                 : kem->keypair;

    SEXP public_key = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)public_size));
    SEXP secret_key = PROTECT(Rf_allocVector(RAWSXP, (R_xlen_t)secret_size));
    int status = keypair((uint8_t *)RAW(public_key), (uint8_t *)RAW(secret_key));
    if (status != 0) {
        secure_zero(RAW(public_key), public_size);
        secure_zero(RAW(secret_key), secret_size);
        Rf_error("key generation failed with status %d", status);
    }

    SEXP result = PROTECT(named_pair(
        public_key, "public_key", secret_key, "secret_key"));
    UNPROTECT(3);
    return result;
}

SEXP kpqc_sign(SEXP algorithm_value, SEXP message, SEXP secret_key,
               SEXP context) {
    const char *id = algorithm_id(algorithm_value);
    const signature_algorithm *algorithm = find_signature(id);
    if (algorithm == NULL) {
        Rf_error("algorithm does not support signatures: %s", id);
    }

    size_t message_size = raw_size(message, "message");
    require_size(secret_key, algorithm->secret_key_size, "secret_key");
    size_t context_size = raw_size(context, "context");
    if (context_size > 255) {
        Rf_error("context cannot exceed 255 bytes");
    }

    SEXP result = PROTECT(Rf_allocVector(
        RAWSXP, (R_xlen_t)algorithm->signature_size));
    uint64_t result_size = 0;
    int status = algorithm->sign(
        (uint8_t *)RAW(result), &result_size, raw_input(message), message_size,
        raw_input(context), context_size, raw_input(secret_key));
    if (status != 0 || result_size != algorithm->signature_size) {
        secure_zero(RAW(result), algorithm->signature_size);
        if (status != 0) {
            Rf_error("signing failed with status %d", status);
        }
        Rf_error("signing returned an invalid signature size");
    }

    UNPROTECT(1);
    return result;
}

SEXP kpqc_verify(SEXP algorithm_value, SEXP message, SEXP signature_value,
                 SEXP public_key, SEXP context) {
    const char *id = algorithm_id(algorithm_value);
    const signature_algorithm *algorithm = find_signature(id);
    if (algorithm == NULL) {
        Rf_error("algorithm does not support signatures: %s", id);
    }

    size_t message_size = raw_size(message, "message");
    size_t signature_size = raw_size(signature_value, "signature");
    require_size(public_key, algorithm->public_key_size, "public_key");
    size_t context_size = raw_size(context, "context");
    if (context_size > 255) {
        Rf_error("context cannot exceed 255 bytes");
    }
    if (signature_size != algorithm->signature_size) {
        return Rf_ScalarLogical(FALSE);
    }

    int status = algorithm->verify(
        raw_input(signature_value), signature_size, raw_input(message),
        message_size, raw_input(context), context_size, raw_input(public_key));
    if (status == -2) {
        Rf_error("verification failed because memory allocation failed");
    }
    return Rf_ScalarLogical(status == 0);
}

SEXP kpqc_encapsulate(SEXP algorithm_value, SEXP public_key) {
    const char *id = algorithm_id(algorithm_value);
    const kem_algorithm *algorithm = find_kem(id);
    if (algorithm == NULL) {
        Rf_error("algorithm does not support KEM operations: %s", id);
    }
    require_size(public_key, algorithm->public_key_size, "public_key");

    SEXP ciphertext = PROTECT(Rf_allocVector(
        RAWSXP, (R_xlen_t)algorithm->ciphertext_size));
    SEXP shared_secret = PROTECT(Rf_allocVector(
        RAWSXP, (R_xlen_t)algorithm->shared_secret_size));
    int status = algorithm->encapsulate(
        (uint8_t *)RAW(ciphertext), (uint8_t *)RAW(shared_secret),
        raw_input(public_key));
    if (status != 0) {
        secure_zero(RAW(ciphertext), algorithm->ciphertext_size);
        secure_zero(RAW(shared_secret), algorithm->shared_secret_size);
        Rf_error("encapsulation failed with status %d", status);
    }

    SEXP result = PROTECT(named_pair(
        ciphertext, "ciphertext", shared_secret, "shared_secret"));
    UNPROTECT(3);
    return result;
}

SEXP kpqc_decapsulate(SEXP algorithm_value, SEXP ciphertext, SEXP secret_key) {
    const char *id = algorithm_id(algorithm_value);
    const kem_algorithm *algorithm = find_kem(id);
    if (algorithm == NULL) {
        Rf_error("algorithm does not support KEM operations: %s", id);
    }
    require_size(ciphertext, algorithm->ciphertext_size, "ciphertext");
    require_size(secret_key, algorithm->secret_key_size, "secret_key");

    SEXP result = PROTECT(Rf_allocVector(
        RAWSXP, (R_xlen_t)algorithm->shared_secret_size));
    int status = algorithm->decapsulate(
        (uint8_t *)RAW(result), raw_input(ciphertext), raw_input(secret_key));
    if (status != 0) {
        secure_zero(RAW(result), algorithm->shared_secret_size);
        Rf_error("decapsulation failed with status %d", status);
    }

    UNPROTECT(1);
    return result;
}

#if defined(KPQC_TEST_ENTROPY)
SEXP kpqc_kat_set_entropy(SEXP algorithm_value, SEXP entropy) {
    const char *id = algorithm_id(algorithm_value);
    const test_entropy_control *control = find_test_entropy_control(id);
    if (control == NULL) {
        Rf_error("unknown KpqC algorithm: %s", id);
    }
    size_t length = raw_size(entropy, "entropy");
    return Rf_ScalarLogical(control->set(raw_input(entropy), length) == 0);
}

SEXP kpqc_kat_clear_entropy(SEXP algorithm_value) {
    const char *id = algorithm_id(algorithm_value);
    const test_entropy_control *control = find_test_entropy_control(id);
    if (control == NULL) {
        Rf_error("unknown KpqC algorithm: %s", id);
    }
    size_t remaining = control->remaining();
    control->clear();
    return Rf_ScalarReal((double)remaining);
}
#endif
