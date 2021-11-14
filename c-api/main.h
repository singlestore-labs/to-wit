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

enum class WITXSigPart {
  Params,
  Results,
  RetPtr,
};

enum class WITXType {
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

struct WITX;

struct WITXFieldIter;

struct WITXFunction;

struct WITXSignature;

struct WITXTypeDef;

struct WITXTypeDefIter;

extern "C" {

const char *witx_error_get();

bool witx_parse(const uint8_t *content, uintptr_t len, WITX **res);

void witx_delete(WITX *witx);

bool witx_func_name_get(const WITXFunction *func, const char **res);

bool witx_func_count_get(const WITX *witx, uintptr_t *res);

bool witx_func_get_by_index(const WITX *witx, uintptr_t index, const WITXFunction **res);

bool witx_func_get_by_name(const WITX *witx, const char *fname, const WITXFunction **res);

bool witx_func_param_walk(const WITXFunction *func, WITXTypeDefIter **res);

bool witx_func_result_walk(const WITXFunction *func, WITXTypeDefIter **res);

bool witx_typedef_iter_off(const WITXTypeDefIter *iter);

bool witx_typedef_iter_next(WITXTypeDefIter *iter);

bool witx_typedef_iter_at(const WITXTypeDefIter *iter, const WITXTypeDef **res);

void witx_typedef_iter_delete(WITXTypeDefIter *iter);

bool witx_record_field_walk(const WITXTypeDef *td, WITXFieldIter **res);

bool witx_field_iter_off(const WITXFieldIter *iter);

bool witx_field_iter_next(WITXFieldIter *iter);

bool witx_field_iter_at(const WITXFieldIter *iter, const WITXTypeDef **res);

void witx_field_iter_delete(WITXFieldIter *iter);

bool witx_array_elem_typedef_get(const WITXTypeDef *td, const WITXTypeDef **res);

bool witx_typedef_name_get(const WITXTypeDef *td, const char **res);

bool witx_typedef_align_get(const WITXTypeDef *td, uintptr_t *res);

bool witx_typedef_type_get(const WITXTypeDef *td, WITXType *res);

bool witx_func_sig_get(const WITXFunction *func, const WITXSignature **res);

bool witx_sig_length_get(const WITXSignature *sig, WITXSigPart part, uintptr_t *res);

bool witx_sig_type_get_by_index(const WITXSignature *sig,
                                WITXSigPart part,
                                uintptr_t idx,
                                WASMType *res);

} // extern "C"
