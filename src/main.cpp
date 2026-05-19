#include "include/VDE.hpp"
#include <iostream>
#include <string>
#include <csignal>
#include <chrono>
#include <thread>
#include <cstring>

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #define PIPE_NAME "\\\\.\\pipe\\VulpineDriverEnginePipe"
#else
    #include <sys/socket.h>
    #include <sys/un.h>
    #include <unistd.h>
    #define SOCKET_PATH "/tmp/vde_engine.sock"
#endif

VDE g_VulpineDriverEngine;
bool g_KeepRunning = true;

void OnOSShutdown(int signal) {
    std::printf("\n[OS Signal] Intercepted termination signal (%d). Shutting down VDE...\n", signal);
    g_KeepRunning = false;
    g_VulpineDriverEngine.Shutdown();
    #if !defined(_WIN32) && !defined(_WIN64)
    unlink(SOCKET_PATH);
    #endif
    std::exit(0);
}

// --- Platform Single-Instance Interfacing ---

#if defined(_WIN32) || defined(_WIN64)
int TryPassToPrimaryInstance(const std::string& path, bool waitForExit) {
    // Open connection to an existing primary instance pipe
    HANDLE hPipe = CreateFileA(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        return -255; // Signifies no primary instance is alive
    }

    // Prefix the payload packet so the daemon knows the routing behavior requested
    std::string packet = (waitForExit ? "WAIT:" : "NOWAIT:") + path;

    DWORD bytesWritten;
    WriteFile(hPipe, packet.c_str(), static_cast<DWORD>(packet.length()), &bytesWritten, NULL);

    int returnedExitCode = 0;

    if (waitForExit) {
        // Block execution thread right here until the daemon crunches bytecode and replies
        DWORD bytesRead = 0;
        char responseBuffer[16] = {0};
        if (ReadFile(hPipe, responseBuffer, sizeof(responseBuffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            returnedExitCode = std::stoi(std::string(responseBuffer, bytesRead));
        }
    }

    CloseHandle(hPipe);
    return returnedExitCode;
}

void RunIPCPipeListener() {
    while (g_KeepRunning) {
        // Changed to PIPE_ACCESS_DUPLEX so we can write back to the proxy
        HANDLE hPipe = CreateNamedPipeA(PIPE_NAME, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 1024, 1024, 0, NULL);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        if (ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED)) {
            char buffer[512] = {0};
            DWORD bytesRead;
            if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
                std::string rawPacket(buffer, bytesRead);
                
                bool clientIsWaiting = (rawPacket.rfind("WAIT:", 0) == 0);
                std::string targetPath = rawPacket.substr(clientIsWaiting ? 5 : 7);

                std::printf("[VDE IPC Channel] Received request for: %s (Wait Mode: %s)\n", 
                            targetPath.c_str(), clientIsWaiting ? "ON" : "OFF");

                int bytecodeExitCode = g_VulpineDriverEngine.LoadAndExecute(targetPath, clientIsWaiting);
                
                if (clientIsWaiting) {
                    std::string response = std::to_string(bytecodeExitCode);
                    DWORD bytesWritten;
                    WriteFile(hPipe, response.c_str(), static_cast<DWORD>(response.length()), &bytesWritten, NULL);
                }
            }
        }
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}
#else
// POSIX Sockets (AlopexOS/Linux) implementation
int TryPassToPrimaryInstance(const std::string& path, bool waitForExit) {
    int clientSock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (clientSock < 0) return -255;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(clientSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(clientSock);
        return -255; 
    }

    std::string packet = (waitForExit ? "WAIT:" : "NOWAIT:") + path;
    send(clientSock, packet.c_str(), packet.length(), 0);

    int returnedExitCode = 0;
    if (waitForExit) {
        char responseBuffer[16] = {0};
        ssize_t bytesRead = recv(clientSock, responseBuffer, sizeof(responseBuffer) - 1, 0);
        if (bytesRead > 0) {
            returnedExitCode = std::stoi(std::string(responseBuffer, bytesRead));
        }
    }

    close(clientSock);
    return returnedExitCode;
}

void RunIPCPipeListener() {
    unlink(SOCKET_PATH);
    int serverSock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverSock < 0) return;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(serverSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 || listen(serverSock, 10) < 0) {
        close(serverSock);
        return;
    }

    while (g_KeepRunning) {
        int clientSock = accept(serverSock, nullptr, nullptr);
        if (clientSock < 0) continue;

        char buffer[512] = {0};
        ssize_t bytesRead = recv(clientSock, buffer, sizeof(buffer) - 1, 0);
        if (bytesRead > 0) {
            std::string rawPacket(buffer, bytesRead);
            bool clientIsWaiting = (rawPacket.rfind("WAIT:", 0) == 0);
            std::string targetPath = rawPacket.substr(clientIsWaiting ? 5 : 7);

            int bytecodeExitCode = g_VulpineDriverEngine.LoadAndExecute(targetPath, clientIsWaiting);
            if (clientIsWaiting) {
                std::string response = std::to_string(bytecodeExitCode);
                send(clientSock, response.c_str(), response.length(), 0);
            }
        }
        close(clientSock);
    }
    close(serverSock);
    unlink(SOCKET_PATH);
}
#endif

// --- System Core Entry Point ---

auto main(int argc, char** argv) -> int {
    std::signal(SIGINT,  OnOSShutdown);
    std::signal(SIGTERM, OnOSShutdown);

    bool waitForExit = true;
    std::string targetPath = "";

    // 1. Process basic CLI flag validations
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--nowait") {
            waitForExit = false;
        } else if (targetPath.empty()) {
            targetPath = arg; // Capture first non-flag argument as target binary file path
        }
    }

    // 2. If a file payload was specified, try passing to the active background daemon
    if (!targetPath.empty()) {
        int ipcResult = TryPassToPrimaryInstance(targetPath, waitForExit);
        if (ipcResult != -255) {
            // Hand-off matched an active listener! Exit proxy process with the engine's true result code
            return ipcResult; 
        }
    }

    // 3. We are the primary instance. Initialize core hardware pooling
    if (g_VulpineDriverEngine.Initialize() != 0) {
        std::printf("[Fatal Error] VDE failed to initialize core hardware layers.\n");
        return 1;
    }

    // 4. Process direct payload targets passed to this first boot context
    if (!targetPath.empty()) {
        std::cout << "[VDE] Launch target requested on boot: " << targetPath << "\n";
        int bootExit = g_VulpineDriverEngine.LoadAndExecute(targetPath, waitForExit);
        
        // If the user specified --wait on the very first boot instance, we exit immediately with the code
        if (waitForExit) {
            g_VulpineDriverEngine.Shutdown();
            return bootExit;
        }
    } else {
        g_VulpineDriverEngine.EnterBackgroundIdlingMode();
    }

    // 5. Transform main execution thread into a duplex IPC broker loop
    std::printf("[VDE Subsystem] Native single-instance IPC stream layer active.\n");
    RunIPCPipeListener();

    return 0;
}