#pragma once
#include <stdint.h>
#include <sys/types.h>

typedef unsigned int (*Sleep_t)(unsigned int);
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
    ExitProcess_t pExitProcess;
    Printf_t pPrintf;
    
    char helloWorldString[18] = "I've been carved!";
    char modS[4] = "%s\n";
} ShellcodeArgs;

extern size_t g_ShellcodeSignature;
void Shellcode(void);
