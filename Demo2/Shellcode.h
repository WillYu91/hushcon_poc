#pragma once
#include <stdint.h>
#include <sys/types.h>

typedef void* (*DlOpen_t)(const char*, int);
typedef void (*ExitProcess_t)(int);
typedef void (*Printf_t)(...);

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
    DlOpen_t pDlopen;
    ExitProcess_t pExitProcess;
    Printf_t pPrintf;
    
    char path[76] = "/Users/test/Desktop/hushcon_poc_build/build/Debug/libSharedObjectPayload.so";
    char modS[28] = "Path: %s loaded at 0x%llx\n";
} ShellcodeArgs;

extern size_t g_ShellcodeSignature;
void Shellcode(void);
