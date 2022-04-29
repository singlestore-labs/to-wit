#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include "to-wit.h"

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

const char *wasmSigPart2Str(WITSigPart part)
{
    switch (part)
    {
        case WITSigPart::Params:  return "Params";
        case WITSigPart::Results: return "Result";
        case WITSigPart::RetPtr:  return "RetPtr";
    }
    assert(false);
    return NULL;
}

const char *witType2Str(WITType wt)
{
    switch (wt)
    {
        case WITType::U8:      return "U8";
        case WITType::U16:     return "U16";
        case WITType::U32:     return "U32";
        case WITType::U64:     return "U64";
        case WITType::S8:      return "S8";
        case WITType::S16:     return "S16";
        case WITType::S32:     return "S32";
        case WITType::S64:     return "S64";
        case WITType::F32:     return "F32";
        case WITType::F64:     return "F64";
        case WITType::Char:    return "Char";
        case WITType::CChar:   return "CChar";
        case WITType::Usize:   return "Usize";
        case WITType::Record:  return "Record";
        case WITType::List:    return "List";
        case WITType::Variant: return "Variant";
        case WITType::Unknown: return "Unknown";
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
                wit_error_get(),    \
                __FILE__,           \
                __LINE__);          \
        exit(1);                    \
    }

void printType(const WITTypeDef* td, int indent)
{
    printIndent(indent);

    const char* name;
    CHECK(wit_typedef_name_get(td, &name));

    WITType ty;
    CHECK(wit_typedef_type_get(td, &ty));

    uintptr_t align;
    CHECK(wit_typedef_align_get(td, &align));

    uintptr_t size;
    CHECK(wit_typedef_size_get(td, &size));

    printf("[name=%s, type=%s, size=%d, align=%d", 
        name, witType2Str(ty), size, align);
    switch (ty)
    {
        case WITType::Variant:
            {
                if (wit_variant_is_bool(td))
                {
                    printf(", kind=bool");
                }
                else if (wit_variant_is_enum(td))
                {
                    printf(", kind=enum");
                }
                else if (wit_variant_is_option(td))
                {
                    printf(", kind=option");
                }
                else if (wit_variant_is_expected(td))
                {
                    printf(", kind=expected");
                }
                uint8_t tag;
                CHECK(wit_variant_tag_get(td, &tag));
                printf(", tag=%d", tag);
            }
            break;

        case WITType::Record:
            {
                if (wit_record_is_tuple(td))
                {
                    printf(", kind=tuple");
                }
                else if (wit_record_is_flags(td))
                {
                    printf(", kind=flags");
                }
            }
            break;

        default:
            break;
    }
    printf("]\n");

    switch (ty)
    {
        case WITType::Record:
            {
                WITFieldIter* fi;
                CHECK(wit_record_field_walk(td, &fi));

                while (!wit_field_iter_off(fi))
                {
                    const WITTypeDef* fty;
                    CHECK(wit_field_iter_at(fi, &fty));

                    printType(fty, indent + 1);
                    CHECK(wit_field_iter_next(fi));
                }
                wit_field_iter_delete(fi);
            }
            break;
        
        case WITType::Variant:
            {
                WITCaseIter* ci;
                CHECK(wit_variant_case_walk(td, &ci));

                while (!wit_case_iter_off(ci))
                {
                    const WITTypeDef* cty;
                    CHECK(wit_case_iter_at(ci, &cty));

                    printType(cty, indent + 1);
                    CHECK(wit_case_iter_next(ci));
                }
                wit_case_iter_delete(ci);
            }
            break;

        case WITType::List:
            {
                const WITTypeDef* ty;
                CHECK(wit_array_elem_typedef_get(td, &ty));

                printType(ty, indent + 1);
            }
            break;

        default:
            break;
    }
}

void printSigPart(const WITSignature* sig, WITSigPart part)
{
    printIndent(1);
    printf("%s: [", wasmSigPart2Str(part));

    size_t len;
    CHECK(wit_sig_length_get(sig, part, &len));

    for (int i = 0; i < len; ++i)
    {
        if (i > 0)
            printf(", ");

        WASMType ty;
        CHECK(wit_sig_type_get_by_index(sig, part, i, &ty));

        printf("%s", wasmType2Str(ty));
    }
    printf("]\n");
}

void printSig(const WITFunction* func)
{
    printf("Signature:\n");

    const WITSignature* sig;
    CHECK(wit_func_sig_get(func, &sig));

    printSigPart(sig, WITSigPart::Params);
    printSigPart(sig, WITSigPart::Results);
    printSigPart(sig, WITSigPart::RetPtr);
}

void printFunc(const WITFunction* func)
{
    printf("Params:\n");
    WITTypeDefIter* tdIter;
    CHECK(wit_func_param_walk(func, &tdIter));
    while (!wit_typedef_iter_off(tdIter))
    {
        const WITTypeDef* td;
        CHECK(wit_typedef_iter_at(tdIter, &td));

        printType(td, 1);

        CHECK(wit_typedef_iter_next(tdIter));
    }
    wit_typedef_iter_delete(tdIter);

    printf("Results:\n");
    CHECK(wit_func_result_walk(func, &tdIter));
    while (!wit_typedef_iter_off(tdIter))
    {
        const WITTypeDef* td;
        CHECK(wit_typedef_iter_at(tdIter, &td));

        printType(td, 1);

        CHECK(wit_typedef_iter_next(tdIter));
    }
    wit_typedef_iter_delete(tdIter);
}

char *readWIT(const char *path, long *len)
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
    char* content = readWIT(argv[1], &contentLen);
    WIT* wit;
    CHECK(wit_parse(reinterpret_cast<uint8_t*>(content), contentLen, &wit));
    free(content);

    if (argc == 2)
    {
        size_t count;
        CHECK(wit_func_count_get(wit, &count));

        printf("Functions:\n");
        for (int i = 0; i < count; ++i)
        {
            const WITFunction* func;
            CHECK(wit_func_get_by_index(wit, i, &func));

            const char* name;
            CHECK(wit_func_name_get(func, &name));

            printf("  %s\n", name);
        }
    }
    else if (argc == 3)
    {
        const char *funcName = argv[2];

        const WITFunction* func;
        CHECK(wit_func_get_by_name(wit, funcName, &func));
    
        printf("Func Name: %s\n", funcName);
        printSig(func);
        printFunc(func);
    }
    wit_delete(wit);

    return 0;
}

