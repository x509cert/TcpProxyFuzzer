// A TCP bi-directional proxy that 
// can act as a bidirectional fuzzer
// Michael Howard (mikehow@microsoft.com)
// Azure Database Security
// Last updated 11/17/2023

#define  _WINSOCK_DEPRECATED_NO_WARNINGS 1

#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <process.h>  
#include <windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <sstream>
#include <iomanip>
#include "gsl/util"
#include "gsl/span"

#pragma comment(lib, "ws2_32.lib")

constexpr auto VERSION = "1.13";
constexpr size_t BUFFER_SIZE = 4096;

// Passes important info to the socket threads 
// because thread APIs only support void* for args
typedef struct {
    SOCKET          src_sock;
    SOCKET          dst_sock;
    int             sock_dir;    // this is the ACTUAL direction of the sockets, client->server (0), server->client (1)
    int             fuzz_dir;    // this is the requested fuzzing direction, c, s, b, n
    unsigned int    fuzz_aggr;   // fuzzing aggressiveness
    int             delay;	     // delay in msec before fuzzing starts, UNUSED
} ConnectionData;

// forward decls
std::string getCurrentTimeAsString();
void forward_data(_In_ const ConnectionData*);
unsigned __stdcall forward_thread(_In_  void*);
bool Fuzz(std::vector<char>& buff, unsigned int fuzzaggr);
bool Fuzz(_Inout_updates_bytes_(*pLen)	char* pBuf,
         _Inout_						unsigned int* pLen,
         _In_					        unsigned int fuzzaggr);

// let's ggoooo...
int main(int argc, char* argv[]) {

    // you must pass in all 6 args
    // TODO: Replace with real arg parsing!
    if (argv==nullptr || argc != 7) {

        fprintf(stdout, "Usage: TcpProxyFuzzer <listen_port> <forward_ip> <forward_port> <start_delay> <aggressiveness> <fuzz_direction>\n");
        fprintf(stdout, "Where:\n\tlisten_port is the proxy listening port. Eg; 8088\n");
        fprintf(stdout, "\tforward_port is the port to proxy requests to. Eg; 80\n");
        fprintf(stdout, "\tforward_ip is the host to forward resuests to. Eg; 192.168.1.77\n");
        fprintf(stdout, "\tstart_delay is how long to wait before fuzzing data in msec. Eg; 100 [Currently ignored and not implemented]\n");
        fprintf(stdout, "\taggressiveness is how agressive the fuzzing should be as a percentage between 0-100. Eg; 7\n");
        fprintf(stdout, "\tfuzz_direction determines whether to fuzz from client->server (s), server->client (c), none (n) or both (b). Eg; s\n");

        return 1;
    }

    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed. Error: %d\n", WSAGetLastError());

        return 1;
    }

    // move argv into a vector for easier parsing
    const gsl::span<char*> argv_span(argv, argc); 
    std::vector<std::string> args(argv_span.begin(), argv_span.end());

    // parse out cmd-line args
    const u_short listen_port         = gsl::narrow_cast<u_short>(std::stoi(args.at(1)));
    const std::string forward_ip      = args.at(2);
    const u_short forward_port        = gsl::narrow_cast<u_short>(std::stoi(args.at(3)));
    const int startdelay              = std::stoi(args.at(4)); // currently unused
    const unsigned int aggressiveness = std::stoi(args.at(5));
    const char direction              = gsl::narrow_cast<const char>(std::tolower(args.at(6).at(0)));

    // basic error checking
    if (listen_port <= 0 || listen_port >= 65535 ||
        aggressiveness < 0 || aggressiveness > 100 ||
        (direction != 'c' && direction != 's' && direction != 'n' && direction != 'b')) {
        fprintf(stderr, "Error in one or more args.");

        return 1;
    }

    const SOCKET server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed. Error: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    SOCKADDR_IN server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(listen_port);

    if (bind(server_sock, reinterpret_cast<SOCKADDR*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed. Error: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    if (listen(server_sock, 10) == SOCKET_ERROR) {
        fprintf(stderr, "Listen failed. Error: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    fprintf(stdout, "TcpProxyFuzzer %s\n", VERSION);
    fprintf(stdout, "Proxying from port %u -> %s:%u\n", listen_port, forward_ip.c_str(), forward_port);

    while (true) {
        const SOCKET client_sock = accept(server_sock, NULL, NULL);
        if (client_sock == INVALID_SOCKET) {
            fprintf(stderr, "Accept failed. Error: %d\n", WSAGetLastError());
            continue;
        }

        const SOCKET target_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (target_sock == INVALID_SOCKET) {
            fprintf(stderr, "Target socket creation failed. Error: %d\n", WSAGetLastError());
            closesocket(client_sock);
            continue;
        }

        SOCKADDR_IN target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        inet_pton(AF_INET, forward_ip.c_str(), &target_addr.sin_addr);
        target_addr.sin_port = htons(forward_port);

        if (connect(target_sock, reinterpret_cast<SOCKADDR*>(&target_addr), sizeof(target_addr)) == SOCKET_ERROR) {
            fprintf(stderr, "Connect to target failed. Error: %d\n", WSAGetLastError());
            closesocket(target_sock);
            closesocket(client_sock);
            continue;
        }

        ConnectionData client_to_target = { client_sock, target_sock, 0, direction, aggressiveness, startdelay };
        ConnectionData target_to_client = { target_sock, client_sock, 1, direction, aggressiveness, startdelay };

        // Create two threads to handle bidirectional forwarding
        _beginthreadex(NULL, 0, forward_thread, &client_to_target, 0, NULL);
        _beginthreadex(NULL, 0, forward_thread, &target_to_client, 0, NULL);
    }

    closesocket(server_sock);
    WSACleanup();

    return 0;
}

// this func handles both server->client and client->server
unsigned __stdcall forward_thread(_In_ void* data) {
    const ConnectionData* connData = static_cast<const ConnectionData*>(data);
    forward_data(connData);

    return 0;
}

void forward_data(_In_ const ConnectionData *connData) {
    char buffer[BUFFER_SIZE]{};
    int bytes_received{};
    bool bFuzz = false;

    // fuzzing only happens in some instances
    if ((connData->fuzz_dir == 'b') 
        || (connData->sock_dir == 1 && connData->fuzz_dir == 'c') 
        || (connData->sock_dir == 0 && connData->fuzz_dir == 's'))
        bFuzz = true;

    auto time = getCurrentTimeAsString();
    auto ctime = time.c_str();

    if (bFuzz)
        fprintf(stderr, "%s\t", ctime);

    // the recv() can be from the client or the server, this code is called on one of two threads
    while ((bytes_received = recv(connData->src_sock, static_cast<char*>(buffer), BUFFER_SIZE, 0)) > 0) {
        
        unsigned int bytes_to_send = bytes_received;

        if (bFuzz)
            Fuzz(static_cast<char*>(buffer), &bytes_to_send, connData->fuzz_aggr);

         send(connData->dst_sock, static_cast<char*>(buffer), bytes_to_send, 0);
    }

    // Clean up the sockets once we're done forwarding
    closesocket(connData->src_sock);
    closesocket(connData->dst_sock);

    if (bFuzz)
        fprintf(stderr, "\n");
}

#pragma warning (push)
#pragma warning(disable : 4996) // localtime
std::string getCurrentTimeAsString() {
    const auto currentTime = std::chrono::system_clock::now();
    const std::time_t currentTime_t = std::chrono::system_clock::to_time_t(currentTime);
    const std::tm* currentTime_tm = std::localtime(&currentTime_t);

    std::ostringstream oss;
    oss << std::put_time(currentTime_tm, "%H:%M:%S");

    return oss.str();
}
#pragma warning (pop)