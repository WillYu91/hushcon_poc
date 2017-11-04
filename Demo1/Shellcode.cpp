#include "Shellcode.h"

size_t g_ShellcodeSignature = SHELLCODEARGS_SIGNATURE;

// Put the shellcode into it's own section
#pragma code_seg(push, shlcd, ".shlcd")
#pragma optimize("", off)
void Shellcode(void)
{    
    ShellcodeArgs* pArgs = (ShellcodeArgs*)(SHELLCODEARGS_SIGNATURE);
    
    pArgs->pPrintf(pArgs->modS, pArgs->helloWorldString);
    
    pArgs->pExitProcess(-1);
}
#pragma optimize("", on)
#pragma code_seg(pop, shlcd)
