#include "Shellcode.h"
#include <dlfcn.h>

size_t g_ShellcodeSignature = SHELLCODEARGS_SIGNATURE;

// Put the shellcode into it's own section
#pragma code_seg(push, shlcd, ".shlcd")
#pragma optimize("", off)
void Shellcode(void)
{    
    ShellcodeArgs* pArgs = (ShellcodeArgs*)(SHELLCODEARGS_SIGNATURE);

    void* pLoadedModule = pArgs->pDlopen(pArgs->path, RTLD_NOW);
    
    pArgs->pPrintf(pArgs->modS, pArgs->path, pLoadedModule);
    
    while (true) { }
}
#pragma optimize("", on)
#pragma code_seg(pop, shlcd)
