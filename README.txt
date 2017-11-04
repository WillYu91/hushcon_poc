This folder contains the demos for the submissions. Use Cmake to build the demos and the supporting binaries. All Demo* binaries take in a pid as a command line argument. They must also be ran as root in order to make the correct system calls.

Demo1 - This demo demonstrates the symbol resolution of a remote processes symbols as well as injection/carving of shell code into a known symbol in a remote process. The end result is a print statement coming from the remote process.

Demo2 - This demo demonstrates everything in demo1, but it also shows how we can leverage the resolution of the dynamic loader symbols in a remote process to load in a rogue dynamic library off of disk via dlopen()

Demo3 - This demo demonstrates everything in demo1, but also shows how we can inject a packed binary into a remote process’s address space. Then using resolved dynamic loader symbols in the remote process, unpack the binary and load it using NSCreateObjectFileImageFromMemory(). It also demonstrates how to resolve the symbols in the newly unpacked and loaded rogue binary in the remote process.

Demo4 - This demo demonstrates everything in demo3, but also shows how we can grab the remote symbols from an unpacked and loaded binary in a remote process even though the binary does not exist on disk and only exists in the remote processes address space.

Victim - This is a dummy application that will be the target of the demos. It will print its pid for ease of use and will continue running in the background until Ctrl-C’d.

SharedObjectPayload - This shared object is used in demo3 to demonstrate loading a rogue library via shell code injection.