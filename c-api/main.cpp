#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include "main.h"

const char *wasmType2Str(WASMType wt)
{
    switch (wt)
    {
        case WASMType::I32: return "I32";
        case WASMType::I64: return "I64";
        case WASMType::F32: return "F32";
        case WASMType::F64: return "F64";
    }
    assert(false);
    return NULL;
}

const char *wasmSigPart2Str(WITXSigPart part)
{
    switch (part)
    {
        case WITXSigPart::Params:  return "Params";
        case WITXSigPart::Results: return "Result";
        case WITXSigPart::RetPtr:  return "RetPtr";
    }
    assert(false);
    return NULL;
}

const char *witxType2Str(WITXType wt)
{
    switch (wt)
    {
        case WITXType::U8:      return "U8";
        case WITXType::U16:     return "U16";
        case WITXType::U32:     return "U32";
        case WITXType::U64:     return "U64";
        case WITXType::S8:      return "S8";
        case WITXType::S16:     return "S16";
        case WITXType::S32:     return "S32";
        case WITXType::S64:     return "S64";
        case WITXType::F32:     return "F32";
        case WITXType::F64:     return "F64";
        case WITXType::Char:    return "Char";
        case WITXType::CChar:   return "CChar";
        case WITXType::Usize:   return "Usize";
        case WITXType::Record:  return "Record";
        case WITXType::List:    return "List";
        case WITXType::Unknown: return "Unknown";
    }
    assert(false);
    return NULL;
}

const char* inStr =
    "record SimpleValue {"                                      "\n"
    "    i: s64,"                                               "\n"
    "}"                                                         "\n"
                                                                "\n"
    "square: function(input: SimpleValue) -> list<SimpleValue>" "\n"
    ;

void printIndent(int level)
{
    for (int i = 0; i < level; ++i)
        printf("  ");
}

#define CHECK(r_)                   \
    if (!(r_))                      \
    {                               \
        fprintf(                    \
            stderr,                 \
            "ERROR: %s (%s, %d)\n", \
                witx_error_get(),   \
                __FILE__,           \
                __LINE__);          \
        exit(1);                    \
    }

void printType(const WITXTypeDef* td, int indent)
{
    printIndent(indent);

    const char* name;
    CHECK(witx_typedef_name_get(td, &name));

    WITXType ty;
    CHECK(witx_typedef_type_get(td, &ty));

    uintptr_t align;
    CHECK(witx_typedef_align_get(td, &align));

    printf("[name=%s, type=%s, align=%d]\n", name, witxType2Str(ty), align);
    switch (ty)
    {
        case WITXType::Record:
            {
                WITXFieldIter* fi;
                CHECK(witx_record_field_walk(td, &fi));

                while (!witx_field_iter_off(fi))
                {
                    const WITXTypeDef* fty;
                    CHECK(witx_field_iter_at(fi, &fty));

                    printType(fty, indent + 1);
                    CHECK(witx_field_iter_next(fi));
                }
                witx_field_iter_delete(fi);
            }
            break;
        
        case WITXType::List:
            {
                const WITXTypeDef* ty;
                CHECK(witx_array_elem_typedef_get(td, &ty));

                printType(ty, indent + 1);
            }
            break;

        default:
            break;
    }
}

void printSigPart(const WITXSignature* sig, WITXSigPart part)
{
    printIndent(1);
    printf("%s: [", wasmSigPart2Str(part));

    size_t len;
    CHECK(witx_sig_length_get(sig, part, &len));

    for (int i = 0; i < len; ++i)
    {
        if (i > 0)
            printf(", ");

        WASMType ty;
        CHECK(witx_sig_type_get_by_index(sig, part, i, &ty));

        printf("%s", wasmType2Str(ty));
    }
    printf("]\n");
}

void printSig(const WITXFunction* func)
{
    printf("Signature:\n");

    const WITXSignature* sig;
    CHECK(witx_func_sig_get(func, &sig));

    printSigPart(sig, WITXSigPart::Params);
    printSigPart(sig, WITXSigPart::Results);
    printSigPart(sig, WITXSigPart::RetPtr);
}

void printFunc(const WITXFunction* func)
{
    printf("Params:\n");
    WITXTypeDefIter* tdIter;
    CHECK(witx_func_param_walk(func, &tdIter));
    while (!witx_typedef_iter_off(tdIter))
    {
        const WITXTypeDef* td;
        CHECK(witx_typedef_iter_at(tdIter, &td));

        printType(td, 1);

        CHECK(witx_typedef_iter_next(tdIter));
    }
    witx_typedef_iter_delete(tdIter);

    printf("Results:\n");
    CHECK(witx_func_result_walk(func, &tdIter));
    while (!witx_typedef_iter_off(tdIter))
    {
        const WITXTypeDef* td;
        CHECK(witx_typedef_iter_at(tdIter, &td));

        printType(td, 1);

        CHECK(witx_typedef_iter_next(tdIter));
    }
    witx_typedef_iter_delete(tdIter);
}

char *readWITX(const char *path, long *len)
{
    FILE* f = fopen(path, "r");
    if (!f)
    {
        perror("Error opening file: ");
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *res = (char *) malloc(sz + 1);
    if (!res)
    {
        fprintf(stderr, "Out of memory!\n");
        exit(1);
    }
    fread(res, 1, sz, f);
    res[sz] = 0;

    fclose(f);
    
    *len = sz;
    return res;
}

void usage(const char *progName)
{
    fprintf(stderr, "Usage: %s PATH [FUNCNAME]\n\n", progName);
    exit(1);
}

int main(int argc, char *argv[])
{
    if (argc < 2 || argc > 3)
        usage(argv[0]);

    long contentLen;
    char* content = readWITX(argv[1], &contentLen);
    WITX* witx;
    CHECK(witx_parse(reinterpret_cast<uint8_t*>(content), contentLen, &witx));
    free(content);

    if (argc == 2)
    {
        size_t count;
        CHECK(witx_func_count_get(witx, &count));

        printf("Functions:\n");
        for (int i = 0; i < count; ++i)
        {
            const WITXFunction* func;
            CHECK(witx_func_get_by_index(witx, i, &func));

            const char* name;
            CHECK(witx_func_name_get(func, &name));

            printf("  %s\n", name);
        }
    }
    else if (argc == 3)
    {
        const char *funcName = argv[2];

        const WITXFunction* func;
        CHECK(witx_func_get_by_name(witx, funcName, &func));
    
        printf("Func Name: %s\n", funcName);
        printSig(func);
        printFunc(func);
    }
    witx_delete(witx);

    return 0;
}

