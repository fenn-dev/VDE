#include "include/VDE.hpp"
#include "include/VXE_Instructions.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <mutex>
#include <thread>

#undef ARCH_64_BIT
#undef ARCH_32_BIT
#undef WIN
#undef UNIX
#undef ARCHTYP

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #define WIN 1
    #define UNIX 0
    #if defined(_M_ARM64) || defined(__aarch64__)
        #define ARCHTYP 3 // ARM64
    #elif defined(_M_X64) || defined(__x86_64__)
        #define ARCHTYP 2 // x86_64
    #else
        #define ARCHTYP 1 // x86
    #endif
#else
    #include <sys/mman.h>
    #include <unistd.h>
    #define WIN 0
    #define UNIX 1
    #if defined(__x86_64__)
        #define ARCHTYP 2 // x86_64
    #elif defined(__aarch64__)
        #define ARCHTYP 3 // ARM64
    #else
        #define ARCHTYP 1 // x86
    #endif
#endif

std::mutex g_TaskMapMutex;

uint64_t native_vxe_alloc(uint64_t size) {
    #if WIN
    return reinterpret_cast<uint64_t>(VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    #else
    void* mem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    return (mem == MAP_FAILED) ? 0 : reinterpret_cast<uint64_t>(mem);
    #endif
}

void native_vxe_free(uint64_t addr) {
    if (!addr) return;
    #if WIN
    VirtualFree(reinterpret_cast<LPVOID>(addr), 0, MEM_RELEASE);
    #else
    // Size tracking would go here for munmap if managing raw POSIX page allocations
    #endif
}

uint64_t native_vxe_write(uint64_t handle, uint64_t buffer, uint64_t len) {
    #if WIN
    DWORD written = 0;
    WriteFile(reinterpret_cast<HANDLE>(handle), reinterpret_cast<LPCVOID>(buffer), static_cast<DWORD>(len), &written, NULL);
    return static_cast<uint64_t>(written);
    #else
    return write(static_cast<int>(handle), reinterpret_cast<const void*>(buffer), len);
    #endif
}

uint64_t native_vxe_read(uint64_t handle, uint64_t buffer, uint64_t len) {
    #if WIN
    DWORD read = 0;
    ReadFile(reinterpret_cast<HANDLE>(handle), reinterpret_cast<LPVOID>(buffer), static_cast<DWORD>(len), &read, NULL);
    return static_cast<uint64_t>(read);
    #else
    return read(static_cast<int>(handle), reinterpret_cast<void*>(buffer), len);
    #endif
}

uint64_t native_vxe_get_args() {
    #if WIN
    return reinterpret_cast<uint64_t>(GetCommandLineA());
    #else
    return 0; // Handled via host environment variables in custom system shells
    #endif
}

#if WIN
void EnsureWindowsFileAssociation() {
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        return; 
    }

    // Added --wait so that file-association launches block until the bytecode finishes
    std::string commandValue = std::string("\"") + exePath + "\" --wait \"%1\"";

    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Classes\\.vxe", 0, NULL, 
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "", 0, REG_SZ, reinterpret_cast<const BYTE*>("Vulpine.Runtime"), 16);
        RegCloseKey(hKey);
    }

    std::string shellKeyPath = "Software\\Classes\\Vulpine.Runtime\\shell\\open\\command";
    if (RegCreateKeyExA(HKEY_CURRENT_USER, shellKeyPath.c_str(), 0, NULL, 
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        
        RegSetValueExA(hKey, "", 0, REG_SZ, 
                       reinterpret_cast<const BYTE*>(commandValue.c_str()), 
                       static_cast<DWORD>(commandValue.length() + 1));
        RegCloseKey(hKey);
    }
}
#endif

auto VDE::Initialize() -> int {
    std::cout << "[VDE] Initializing hardware abstraction layers and memory pools...\n";
    
    #if WIN
    std::cout << "[VDE Windows Guard] Validating file system registry hooks...\n";
    EnsureWindowsFileAssociation();
    #endif

    isidling = false;
    return 0;
}

auto VDE::EnterBackgroundIdlingMode() -> int {
    std::cout << "[VDE] No executable targeted. Entering background resident idle loop\n";
    isidling = true;
    return 0;
}

auto VDE::ExitBackgroundIdlingMode() -> int {
    if (isidling) {
        std::cout << "[VDE] Execution request trapped. Waking up engine pipeline.\n";
        isidling = false;
    }
    return 0;
}

auto VDE::LoadAndExecute(std::string path, bool wait) -> int {
    ExitBackgroundIdlingMode();
    
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::printf("[VDE Error] Failed to open file: %s\n", path.c_str());
        return -1;
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    if (fileSize == 0) {
        std::printf("[VDE Error] File is empty: %s\n", path.c_str());
        return -2;
    }

    std::vector<uint8_t> localBytes(fileSize);
    file.read(reinterpret_cast<char*>(localBytes.data()), fileSize);
    file.close();

    size_t cursor = 0;
    uint8_t archCounts = localBytes[cursor++];

    ArchHeader targetSlice{0, 0, 0};
    bool sliceFound = false;
    uint8_t hostArchTarget = ARCHTYP;

    for (uint8_t i = 0; i < archCounts; ++i) {
        ArchHeader currentSlice;
        currentSlice.archID = localBytes[cursor++];
        
        currentSlice.bytecodeOffset = 0;
        for (int b = 0; b < 8; ++b) {
            currentSlice.bytecodeOffset |= (static_cast<uint64_t>(localBytes[cursor++]) << (b * 8));
        }

        currentSlice.bytecodeSize = 0;
        for (int b = 0; b < 8; ++b) {
            currentSlice.bytecodeSize |= (static_cast<uint64_t>(localBytes[cursor++]) << (b * 8));
        }

        if (currentSlice.archID == hostArchTarget) {
            targetSlice = currentSlice;
            sliceFound = true;
        }
    }

    uint8_t delimiter = localBytes[cursor++];
    if (delimiter != 0x00) {
        std::printf("[VDE Error] Corrupt .vxe structure. Header missing validation delimiter.\n");
        return -3;
    }

    if (!sliceFound) {
        std::printf("[VDE Error] Binary lacks execution layer for architecture target %d\n", hostArchTarget);
        return -4;
    }

    uint64_t taskId;
    const uint8_t* codePayloadPtr = nullptr;
    size_t codePayloadSize = 0;

    {
        std::lock_guard<std::mutex> lock(g_TaskMapMutex);
        taskId = nextTaskId++;
        RunningTask& newTask = activeTasks[taskId];
        newTask.taskId = taskId;
        newTask.programName = path;
        newTask.binaryBuffer = std::move(localBytes);

        codePayloadPtr = newTask.binaryBuffer.data() + targetSlice.bytecodeOffset;
        codePayloadSize = targetSlice.bytecodeSize;
    }

    if (wait) {
        return this->run(codePayloadPtr, codePayloadSize, taskId);
    } else {
        std::printf("[VDE] Spawning Worker Thread for %s (ID: %llu, Target Offset: 0x%llX)\n", 
                    path.c_str(), taskId, targetSlice.bytecodeOffset);
        std::thread t(&VDE::run, this, codePayloadPtr, codePayloadSize, taskId);
        t.detach();
        return 0;
    }
}

auto VDE::Shutdown() -> int {
    std::cout << "[VDE] Shutting down hardware abstraction layers and memory pools...\n";
    return 0;
}

auto VDE::run(const uint8_t* codeBuffer, size_t size, uint64_t taskId) -> int {
    if (size == 0 || !codeBuffer) return -1;

    VXE_Context ctx;
    ctx.vxe_alloc    = native_vxe_alloc;
    ctx.vxe_free     = native_vxe_free;
    ctx.vxe_write    = native_vxe_write;
    ctx.vxe_read     = native_vxe_read;
    ctx.vxe_get_args = native_vxe_get_args;

    #if UNIX
    void* execMem = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    #else
    void* execMem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    #endif
    std::memcpy(execMem, codeBuffer, size);

    uint64_t final_exit_code = 0;

    #if defined(_M_X64) || defined(__x86_64__)
    unsigned char thunk_code[] = {
        0x53,                               // push rbx
        0x48, 0x89, 0xCB,                   // mov rbx, rcx
        0x48, 0x89, 0xD0,                   // mov rax, rdx
        0x48, 0x89, 0xDF,                   // mov rdi, rbx
        0x48, 0x83, 0xEC, 0x20,             // sub rsp, 32
        0xFF, 0xD0,                         // call rax
        0x48, 0x83, 0xC4, 0x20,             // add rsp, 32
        0x5B,                               // pop rbx
        0xC3                                // ret
    };

    #if UNIX
    void* thunk_mem = mmap(nullptr, sizeof(thunk_code), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    #else
    void* thunk_mem = VirtualAlloc(nullptr, sizeof(thunk_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    #endif

    if (thunk_mem) {
        std::memcpy(thunk_mem, thunk_code, sizeof(thunk_code));
        
        using thunk_entry_t = uint64_t(*)(void* ctx, void* entry);
        thunk_entry_t run_bridge = reinterpret_cast<thunk_entry_t>(thunk_mem);
        
        std::printf("[VDE Engine] Transferring instruction pointer to hardware...\n");
        final_exit_code = run_bridge(&ctx, execMem);
        
        #if UNIX
        munmap(thunk_mem, sizeof(thunk_code));
        #else
        VirtualFree(thunk_mem, 0, MEM_RELEASE);
        #endif
    }
    #else
    std::printf("[VDE Engine] Transferring instruction pointer to hardware...\n");
    using vxe_entry_t = uint64_t(*)(void* ctx);
    vxe_entry_t bin_entry = reinterpret_cast<vxe_entry_t>(execMem);
    final_exit_code = bin_entry(&ctx);
    #endif

    #if UNIX
    munmap(execMem, size);
    #else
    VirtualFree(execMem, 0, MEM_RELEASE);
    #endif

    std::printf("[VDE Async Loop] Execution Complete. Thread Exiting. Result Code: %llu\n", final_exit_code);
    
    // --- Safe Memory Unloading & Task Map Cleanup ---
    {
        std::lock_guard<std::mutex> lock(g_TaskMapMutex);
        activeTasks.erase(taskId);
    }

    return static_cast<int>(final_exit_code);
}