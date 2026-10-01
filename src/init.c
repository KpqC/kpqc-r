/* SPDX-License-Identifier: MIT */
#define R_NO_REMAP
#include <R.h>
#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>
#include <Rinternals.h>

extern SEXP kpqc_keypair(SEXP);
extern SEXP kpqc_sign(SEXP, SEXP, SEXP, SEXP);
extern SEXP kpqc_verify(SEXP, SEXP, SEXP, SEXP, SEXP);
extern SEXP kpqc_encapsulate(SEXP, SEXP);
extern SEXP kpqc_decapsulate(SEXP, SEXP, SEXP);
#if defined(KPQC_TEST_ENTROPY)
extern SEXP kpqc_kat_set_entropy(SEXP, SEXP);
extern SEXP kpqc_kat_clear_entropy(SEXP);
extern SEXP kpqc_kat_drbg_init(SEXP);
extern SEXP kpqc_kat_drbg_generate(SEXP);
extern SEXP kpqc_kat_drbg_clear(void);
#endif

static const R_CallMethodDef call_methods[] = {
    {"kpqc_keypair", (DL_FUNC)&kpqc_keypair, 1},
    {"kpqc_sign", (DL_FUNC)&kpqc_sign, 4},
    {"kpqc_verify", (DL_FUNC)&kpqc_verify, 5},
    {"kpqc_encapsulate", (DL_FUNC)&kpqc_encapsulate, 2},
    {"kpqc_decapsulate", (DL_FUNC)&kpqc_decapsulate, 3},
#if defined(KPQC_TEST_ENTROPY)
    {"kpqc_kat_set_entropy", (DL_FUNC)&kpqc_kat_set_entropy, 2},
    {"kpqc_kat_clear_entropy", (DL_FUNC)&kpqc_kat_clear_entropy, 1},
    {"kpqc_kat_drbg_init", (DL_FUNC)&kpqc_kat_drbg_init, 1},
    {"kpqc_kat_drbg_generate", (DL_FUNC)&kpqc_kat_drbg_generate, 1},
    {"kpqc_kat_drbg_clear", (DL_FUNC)&kpqc_kat_drbg_clear, 0},
#endif
    {NULL, NULL, 0},
};

void attribute_visible R_init_kpqc(DllInfo *dll) {
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
}
