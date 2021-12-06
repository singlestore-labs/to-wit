#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

enum class WASMType {
  I32,
  I64,
  F32,
  F64,
};

enum class WITSigPart {
  Params,
  Results,
  RetPtr,
};

enum class WITType {
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

struct WIT;

struct WITFieldIter;

struct WITFunction;

struct WITSignature;

struct WITTypeDef;

struct WITTypeDefIter;

extern "C" {

const char *wit_error_get();

bool wit_parse(const uint8_t *content, uintptr_t len, WIT **res);

void wit_delete(WIT *wit);

bool wit_func_name_get(const WITFunction *func, const char **res);

bool wit_func_count_get(const WIT *wit, uintptr_t *res);

bool wit_func_get_by_index(const WIT *wit, uintptr_t index, const WITFunction **res);

bool wit_func_get_by_name(const WIT *wit, const char *fname, const WITFunction **res);

bool wit_func_param_walk(const WITFunction *func, WITTypeDefIter **res);

bool wit_func_result_walk(const WITFunction *func, WITTypeDefIter **res);

bool wit_typedef_iter_off(const WITTypeDefIter *iter);

bool wit_typedef_iter_next(WITTypeDefIter *iter);

bool wit_typedef_iter_at(const WITTypeDefIter *iter, const WITTypeDef **res);

void wit_typedef_iter_delete(WITTypeDefIter *iter);

bool wit_record_field_walk(const WITTypeDef *td, WITFieldIter **res);

bool wit_field_iter_off(const WITFieldIter *iter);

bool wit_field_iter_next(WITFieldIter *iter);

bool wit_field_iter_at(const WITFieldIter *iter, const WITTypeDef **res);

void wit_field_iter_delete(WITFieldIter *iter);

bool wit_array_elem_typedef_get(const WITTypeDef *td, const WITTypeDef **res);

bool wit_typedef_name_get(const WITTypeDef *td, const char **res);

bool wit_typedef_align_get(const WITTypeDef *td, uintptr_t *res);

bool wit_typedef_size_get(const WITTypeDef *td, uintptr_t *res);

bool wit_typedef_type_get(const WITTypeDef *td, WITType *res);

bool wit_func_sig_get(const WITFunction *func, const WITSignature **res);

bool wit_sig_length_get(const WITSignature *sig, WITSigPart part, uintptr_t *res);

bool wit_sig_type_get_by_index(const WITSignature *sig,
                               WITSigPart part,
                               uintptr_t idx,
                               WASMType *res);

} // extern "C"
