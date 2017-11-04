#pragma once
#include <stdint.h>
#include <sys/types.h>
#include <mach-o/dyld.h>

typedef void (*ExitProcess_t)(int);
typedef void (*Printf_t)(...);
typedef NSObjectFileImageReturnCode (*NSCreateObjectFile_t)(void*, size_t, NSObjectFileImage*);
typedef NSModule (*NSLinkModule_t)(NSObjectFileImage, const char*, int);
typedef NSSymbol(*NSLookupSymbolInModule_t)(NSModule, const char*);
typedef void(*DoSomethingFunction_t)(uint32_t);
typedef void*(*NSAddressOfSymbol_t)(NSSymbol);


#pragma pack(push, 1)
typedef struct _FunctionRouter
{
    uint8_t  jmp;
    uint64_t addr;
} FunctionRouter;
#pragma pack(pop)

#define SHELLCODEARGS_SIGNATURE (size_t)0x5A5A5A5A5A5A5A5A

typedef struct _ShellcodeArgs
{
    Printf_t                 pPrintf;
    NSCreateObjectFile_t     pNSCreateObjectFile;
    NSLookupSymbolInModule_t pNSLookUpSymbol;
    NSLinkModule_t           pNSLinkModule;
    NSAddressOfSymbol_t      pNSAddressOfSymbol;
    
    void*    pModuleLocation;
    size_t   sizeOfModule;
    
    char empty[1] = "";
    char symbol[13] = "_DoSomething";
    char message[13] = "Unpacking...";
    
} ShellcodeArgs;

extern size_t g_ShellcodeSignature;
void Shellcode(void);
