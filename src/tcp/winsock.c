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
/* Loop #79: the listener's own codes. */
#define MB_TCP_ERR_LISTEN (-5)
#define MB_TCP_ERR_ACCEPT (-6)
/* "nothing arrived before the deadline" -- not an error, and NOT the same
 * thing as a failed accept. The MoonBit side has to tell them apart: a
 * timeout means "ask again", an error means "stop". */
#define MB_TCP_ERR_TIMEOUT (-7)

static int mb_wsa_ready = 0;

/* Loop #79: how many sockets are open.
 *
 * This counter exists because of a real defect. `mb_tcp_close` used to call
 * WSACleanup() on EVERY close, which is wrong as soon as there is more than
 * one socket -- and a local forward has three of them (the listening socket,
 * the SSH connection, and the accepted connection). Closing the SSH
 * connection would then have torn Winsock down underneath the listener, and
 * the symptom would have been "the listener died when the first connection
 * ended", which is nothing like what the code appears to do.
 *
 * WSACleanup is now called when the LAST socket closes, which is the only
 * point at which it is correct. */
static int mb_tcp_open_sockets = 0;

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

static long long mb_tcp_track(SOCKET s) {
    mb_tcp_open_sockets++;
    return (long long)(intptr_t)s;
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
    return mb_tcp_track(s);
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
    /* Loop #79: WSACleanup only when the LAST socket goes. See the counter's
     * comment: with a listener, an SSH connection and an accepted connection
     * alive at once, tearing Winsock down on the first close would kill the
     * listener underneath the forward. */
    if (mb_tcp_open_sockets > 0) {
        mb_tcp_open_sockets--;
    }
    if (mb_tcp_open_sockets == 0 && mb_wsa_ready) {
        WSACleanup();
        mb_wsa_ready = 0;
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Loop #79: the listening socket.
 *
 * `ssh -L 9000:db:5432 host` needs a local listener: the client listens, and
 * for every connection it accepts it opens a "direct-tcpip" channel. Loop #76
 * built the channel; nothing listened.
 * -------------------------------------------------------------------------- */

/* Bind and listen in one step, because a MoonBit caller that got a bound
 * socket but could not listen would have no way to tell the two apart. */
long long mb_tcp_listen(unsigned char *host, int host_len, int port) {
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
    /* A gate binds and rebinds the same port over and over. Without
     * SO_REUSEADDR a socket left in TIME_WAIT by the previous run makes
     * bind() fail, and that failure reads like "something else is using the
     * port" when the truth is "we used it a minute ago". */
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, hostbuf, &addr.sin_addr) != 1) {
        closesocket(s);
        return MB_TCP_ERR_HOST;
    }
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return MB_TCP_ERR_LISTEN;
    }
    if (listen(s, 16) != 0) {
        closesocket(s);
        return MB_TCP_ERR_LISTEN;
    }
    return mb_tcp_track(s);
}

/* The port the listening socket actually got.
 *
 * The caller asked for port 0 to mean "you pick", and then it has to know
 * which port it got -- it cannot connect to its own listener otherwise. So
 * this reads the port back off the socket with getsockname rather than
 * echoing the request back.
 *
 * The port comes back as 2 big-endian bytes. Two, not four: the value is
 * 16 bits, and reading it cannot overflow. */
int mb_tcp_local_port(long long h, unsigned char *port_out) {
    SOCKET s = (SOCKET)(intptr_t)h;
    struct sockaddr_in addr;
    int len = (int)sizeof(addr);
    unsigned short p;

    if (h < 0 || getsockname(s, (struct sockaddr *)&addr, &len) != 0) {
        return -1;
    }
    p = ntohs(addr.sin_port);
    port_out[0] = (unsigned char)((p >> 8) & 0xFF);
    port_out[1] = (unsigned char)(p & 0xFF);
    return 0;
}

/* Accept one connection, or say that nothing arrived before the deadline.
 *
 * The deadline is the point of this function. A blocking accept() cannot be
 * interrupted, so the driver could never decide to stop listening, and the
 * only way out would be for the process to be killed -- which is not a
 * shutdown, it is an abort. select() gives the caller a deadline it can
 * check, and MB_TCP_ERR_TIMEOUT says "nothing yet" as something distinct
 * from "the accept failed".
 *
 * The peer's address is filled in because the "direct-tcpip" payload has to
 * carry an originator, and the honest value for it is the address of the
 * connection we just accepted. Loop #76 had to make one up ("127.0.0.1", 0)
 * because nothing was listening; now that something is, the real address is
 * available and the server's log can be checked against it.
 *
 * The address comes back in ONE 8-byte buffer -- 4 bytes of IPv4 address
 * then 2 bytes of big-endian port, then 2 bytes of padding -- rather than in
 * two of them. Two reasons, and neither of them is tidiness:
 *
 *   - MoonBit's #borrow annotation names one borrowed parameter, and a
 *     second borrowed pointer would need a spelling this repository has not
 *     used anywhere yet. One buffer keeps the ABI to what is already proven
 *     to work (see mb_tcp_recv, which fills a buffer the caller reads back).
 *   - The port is 16 bits, so two bytes are enough, and reading two bytes
 *     cannot overflow. A four-byte port would have to be read with an
 *     intermediate wide enough to hold 0xFFFFFFFF, and an Int32 that
 *     overflows is a panic in a debug build -- a helper that panics on a
 *     value it should never see is a trap. */
long long mb_tcp_accept(long long h, unsigned char *peer, int timeout_ms) {
    SOCKET s = (SOCKET)(intptr_t)h;
    struct sockaddr_in addr;
    int len = (int)sizeof(addr);
    int one = 1;
    SOCKET c;
    fd_set readable;
    struct timeval tv;
    unsigned char *ip;
    unsigned short pp;
    int ready;

    if (h < 0) {
        return MB_TCP_ERR_ACCEPT;
    }
    FD_ZERO(&readable);
    FD_SET(s, &readable);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    /* On Windows the first argument is ignored and must be zero. */
    ready = select(0, &readable, NULL, NULL, &tv);
    if (ready == 0) {
        return MB_TCP_ERR_TIMEOUT;
    }
    if (ready < 0) {
        return MB_TCP_ERR_ACCEPT;
    }
    c = accept(s, (struct sockaddr *)&addr, &len);
    if (c == INVALID_SOCKET) {
        return MB_TCP_ERR_ACCEPT;
    }
    ip = (unsigned char *)&addr.sin_addr;
    peer[0] = ip[0];
    peer[1] = ip[1];
    peer[2] = ip[2];
    peer[3] = ip[3];
    pp = ntohs(addr.sin_port);
    peer[4] = (unsigned char)((pp >> 8) & 0xFF);
    peer[5] = (unsigned char)(pp & 0xFF);
    peer[6] = 0;
    peer[7] = 0;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
    return mb_tcp_track(c);
}
