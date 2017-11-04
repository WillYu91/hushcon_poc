#include <iostream>
#include <string>
#include <unistd.h>

extern "C"
void DoSomething(uint32_t keepAliveSeconds)
{
    std::cout << "In the function " << __FUNCTION__ << std::endl;
    sleep(keepAliveSeconds);
}

__attribute__((constructor)) static void OnLoad (void)
{
    std::cout << "Payload library loaded!" << std::endl;
    return;
}

__attribute__((destructor)) static void OnUnload(void)
{
    return;
}
