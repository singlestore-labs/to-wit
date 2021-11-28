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

const char *wasmSigPart2Str(WAISigPart part)
{
    switch (part)
    {
        case WAISigPart::Params:  return "Params";
        case WAISigPart::Results: return "Result";
        case WAISigPart::RetPtr:  return "RetPtr";
    }
    assert(false);
    return NULL;
}

const char *waiType2Str(WAIType wt)
{
    switch (wt)
    {
        case WAIType::U8:      return "U8";
        case WAIType::U16:     return "U16";
        case WAIType::U32:     return "U32";
        case WAIType::U64:     return "U64";
        case WAIType::S8:      return "S8";
        case WAIType::S16:     return "S16";
        case WAIType::S32:     return "S32";
        case WAIType::S64:     return "S64";
        case WAIType::F32:     return "F32";
        case WAIType::F64:     return "F64";
        case WAIType::Char:    return "Char";
        case WAIType::CChar:   return "CChar";
        case WAIType::Usize:   return "Usize";
        case WAIType::Record:  return "Record";
        case WAIType::List:    return "List";
        case WAIType::Unknown: return "Unknown";
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
                wai_error_get(),    \
                __FILE__,           \
                __LINE__);          \
        exit(1);                    \
    }

void printType(const WAITypeDef* td, int indent)
{
    printIndent(indent);

    const char* name;
    CHECK(wai_typedef_name_get(td, &name));

    WAIType ty;
    CHECK(wai_typedef_type_get(td, &ty));

    uintptr_t align;
    CHECK(wai_typedef_align_get(td, &align));

    uintptr_t size;
    CHECK(wai_typedef_size_get(td, &size));

    printf("[name=%s, type=%s, size=%d, align=%d]\n", name, waiType2Str(ty), size, align);
    switch (ty)
    {
        case WAIType::Record:
            {
                WAIFieldIter* fi;
                CHECK(wai_record_field_walk(td, &fi));

                while (!wai_field_iter_off(fi))
                {
                    const WAITypeDef* fty;
                    CHECK(wai_field_iter_at(fi, &fty));

                    printType(fty, indent + 1);
                    CHECK(wai_field_iter_next(fi));
                }
                wai_field_iter_delete(fi);
            }
            break;
        
        case WAIType::List:
            {
                const WAITypeDef* ty;
                CHECK(wai_array_elem_typedef_get(td, &ty));

                printType(ty, indent + 1);
            }
            break;

        default:
            break;
    }
}

void printSigPart(const WAISignature* sig, WAISigPart part)
{
    printIndent(1);
    printf("%s: [", wasmSigPart2Str(part));

    size_t len;
    CHECK(wai_sig_length_get(sig, part, &len));

    for (int i = 0; i < len; ++i)
    {
        if (i > 0)
            printf(", ");

        WASMType ty;
        CHECK(wai_sig_type_get_by_index(sig, part, i, &ty));

        printf("%s", wasmType2Str(ty));
    }
    printf("]\n");
}

void printSig(const WAIFunction* func)
{
    printf("Signature:\n");

    const WAISignature* sig;
    CHECK(wai_func_sig_get(func, &sig));

    printSigPart(sig, WAISigPart::Params);
    printSigPart(sig, WAISigPart::Results);
    printSigPart(sig, WAISigPart::RetPtr);
}

void printFunc(const WAIFunction* func)
{
    printf("Params:\n");
    WAITypeDefIter* tdIter;
    CHECK(wai_func_param_walk(func, &tdIter));
    while (!wai_typedef_iter_off(tdIter))
    {
        const WAITypeDef* td;
        CHECK(wai_typedef_iter_at(tdIter, &td));

        printType(td, 1);

        CHECK(wai_typedef_iter_next(tdIter));
    }
    wai_typedef_iter_delete(tdIter);

    printf("Results:\n");
    CHECK(wai_func_result_walk(func, &tdIter));
    while (!wai_typedef_iter_off(tdIter))
    {
        const WAITypeDef* td;
        CHECK(wai_typedef_iter_at(tdIter, &td));

        printType(td, 1);

        CHECK(wai_typedef_iter_next(tdIter));
    }
    wai_typedef_iter_delete(tdIter);
}

char *readWAI(const char *path, long *len)
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
    char* content = readWAI(argv[1], &contentLen);
    WAI* wai;
    CHECK(wai_parse(reinterpret_cast<uint8_t*>(content), contentLen, &wai));
    free(content);

    if (argc == 2)
    {
        size_t count;
        CHECK(wai_func_count_get(wai, &count));

        printf("Functions:\n");
        for (int i = 0; i < count; ++i)
        {
            const WAIFunction* func;
            CHECK(wai_func_get_by_index(wai, i, &func));

            const char* name;
            CHECK(wai_func_name_get(func, &name));

            printf("  %s\n", name);
        }
    }
    else if (argc == 3)
    {
        const char *funcName = argv[2];

        const WAIFunction* func;
        CHECK(wai_func_get_by_name(wai, funcName, &func));
    
        printf("Func Name: %s\n", funcName);
        printSig(func);
        printFunc(func);
    }
    wai_delete(wai);

    return 0;
}

