/* Loop #31: blocking TCP transport for the native backend.
 *
 * Winsock2 wrapper. SSH is a strict request/response protocol -- the client
 * must read exactly the bytes the server sent before it can compute anything
 * -- so a blocking socket is the honest shape here. The browser backend in
 * Loop #32 supplies the same read/write contract over WebTransport instead.
 *
 * Two ABI details drive the signatures:
 *   - A SOCKET is UINT_PTR, 64-bit on win64, so it travels as long long.
 *     Truncating it to int would corrupt handles above 2^31.
 *   - A MoonBit String is not NUL-terminated, so the host is passed as
 *     (pointer, length) and copied into a terminated buffer here. Handing
 *     inet_pton a raw MoonBit String makes it read past the end of the data.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

/* Distinct negative codes so a failure stage is visible from MoonBit instead
 * of collapsing into one opaque "could not connect". */
#define MB_TCP_ERR_STARTUP (-1)
#define MB_TCP_ERR_SOCKET (-2)
#define MB_TCP_ERR_HOST (-3)
#define MB_TCP_ERR_CONNECT (-4)

static int mb_wsa_ready = 0;

static int mb_tcp_startup(void) {
    WSADATA wsa;
    if (mb_wsa_ready) {
        return 0;
    }
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return -1;
    }
    mb_wsa_ready = 1;
    return 0;
}

long long mb_tcp_connect(unsigned char *host, int host_len, int port) {
    SOCKET s;
    struct sockaddr_in addr;
    int one = 1;
    char hostbuf[256];

    if (mb_tcp_startup() != 0) {
        return MB_TCP_ERR_STARTUP;
    }
    if (host_len < 1 || host_len > 255) {
        return MB_TCP_ERR_HOST;
    }
    memcpy(hostbuf, host, (size_t)host_len);
    hostbuf[host_len] = '\0';

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        return MB_TCP_ERR_SOCKET;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, hostbuf, &addr.sin_addr) != 1) {
        closesocket(s);
        return MB_TCP_ERR_HOST;
    }
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return MB_TCP_ERR_CONNECT;
    }
    /* SSH packets are small and strictly ordered; Nagle would add latency
     * for no throughput gain. */
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
    return (long long)(intptr_t)s;
}

long long mb_tcp_send(long long h, unsigned char *buf, int off, int n) {
    SOCKET s = (SOCKET)(intptr_t)h;
    int nsend = send(s, (const char *)(buf + off), n, 0);
    if (nsend == SOCKET_ERROR) {
        return -1;
    }
    return (long long)nsend;
}

long long mb_tcp_recv(long long h, unsigned char *buf, int n) {
    SOCKET s = (SOCKET)(intptr_t)h;
    int nread = recv(s, (char *)buf, n, 0);
    if (nread == SOCKET_ERROR) {
        return -1;
    }
    return (long long)nread;
}

int mb_tcp_close(long long h) {
    SOCKET s = (SOCKET)(intptr_t)h;
    if (h < 0) {
        return -1;
    }
    closesocket(s);
    if (mb_wsa_ready) {
        WSACleanup();
        mb_wsa_ready = 0;
    }
    return 0;
}
