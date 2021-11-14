#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

enum class WAISigPart {
  Params,
  Results,
  RetPtr,
};

enum class WAIType {
  U8,
  U16,
  U32,
  U64,
  S8,
  S16,
  S32,
  S64,
  F32,
  F64,
  Char,
  CChar,
  Usize,
  Record,
  List,
  Unknown,
};

enum class WASMType {
  I32,
  I64,
  F32,
  F64,
};

struct WAI;

struct WAIFieldIter;

struct WAIFunction;

struct WAISignature;

struct WAITypeDef;

struct WAITypeDefIter;

extern "C" {

const char *wai_error_get();

bool wai_parse(const uint8_t *content, uintptr_t len, WAI **res);

void wai_delete(WAI *wai);

bool wai_func_name_get(const WAIFunction *func, const char **res);

bool wai_func_count_get(const WAI *wai, uintptr_t *res);

bool wai_func_get_by_index(const WAI *wai, uintptr_t index, const WAIFunction **res);

bool wai_func_get_by_name(const WAI *wai, const char *fname, const WAIFunction **res);

bool wai_func_param_walk(const WAIFunction *func, WAITypeDefIter **res);

bool wai_func_result_walk(const WAIFunction *func, WAITypeDefIter **res);

bool wai_typedef_iter_off(const WAITypeDefIter *iter);

bool wai_typedef_iter_next(WAITypeDefIter *iter);

bool wai_typedef_iter_at(const WAITypeDefIter *iter, const WAITypeDef **res);

void wai_typedef_iter_delete(WAITypeDefIter *iter);

bool wai_record_field_walk(const WAITypeDef *td, WAIFieldIter **res);

bool wai_field_iter_off(const WAIFieldIter *iter);

bool wai_field_iter_next(WAIFieldIter *iter);

bool wai_field_iter_at(const WAIFieldIter *iter, const WAITypeDef **res);

void wai_field_iter_delete(WAIFieldIter *iter);

bool wai_array_elem_typedef_get(const WAITypeDef *td, const WAITypeDef **res);

bool wai_typedef_name_get(const WAITypeDef *td, const char **res);

bool wai_typedef_align_get(const WAITypeDef *td, uintptr_t *res);

bool wai_typedef_type_get(const WAITypeDef *td, WAIType *res);

bool wai_func_sig_get(const WAIFunction *func, const WAISignature **res);

bool wai_sig_length_get(const WAISignature *sig, WAISigPart part, uintptr_t *res);

bool wai_sig_type_get_by_index(const WAISignature *sig,
                               WAISigPart part,
                               uintptr_t idx,
                               WASMType *res);

} // extern "C"
