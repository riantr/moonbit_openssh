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
#include <stdio.h>
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
/* Loop #83: the name did not resolve to any address. This is a different
 * problem from "the connection failed" and it needs a different answer: one
 * is a typo in the host name (or a missing DNS entry), the other is a
 * server that is not listening. */
#define MB_TCP_ERR_RESOLVE (-8)
/* Loop #83: every address ran out of time before the connect finished. */
#define MB_TCP_ERR_CONNECT_TIMEOUT (-9)

/* --------------------------------------------------------------------------
 * Loop #83: the report a connect writes back.
 *
 * A connect stopped being one thing once host names were resolved: the name
 * may map to several addresses, each of which may be tried, and each may
 * fail in its own way. So the connect writes back what it did, and the
 * MoonBit side turns that into a report.
 *
 * One buffer with a fixed layout, rather than a struct. A struct's layout is
 * the compiler's business, and this one crosses a language boundary where
 * both sides have to agree on it byte for byte -- so the integers are
 * written out byte by byte, little-endian, and nothing depends on the
 * alignment or the padding a compiler would have chosen.
 *
 *   offset  size  what
 *   0       4     how many addresses the name resolved to
 *   4       4     which of them we ended up on (0xFFFFFFFF = none)
 *   8       4     status: 0 connected, 1 resolve failed, 2 connect failed,
 *                 3 timed out
 *   12      4     the winsock error of the last failure (0 if there was none)
 *   16      4     which address failed last (0xFFFFFFFF = none)
 *   20      16    one byte per address: 0 not tried, 1 connected, 2 failed,
 *                 3 ran out of time
 *   36      64*n  the numeric text of each address, in the resolver's order
 *
 * The address texts are the *numeric* form, the way OpenSSH prints them
 * ("Connecting to %.200s [%.100s] port %s." in sshconnect.c) -- a name in
 * the output would be a name we were asked to connect to, not the address we
 * actually reached.
 * -------------------------------------------------------------------------- */
#define MB_TCP_MAX_ADDRS 16
#define MB_TCP_ADDR_TEXT 64
#define MB_TCP_REPORT_COUNT 0
#define MB_TCP_REPORT_CHOSEN 4
#define MB_TCP_REPORT_STATUS 8
#define MB_TCP_REPORT_ERROR 12
#define MB_TCP_REPORT_LASTFAIL 16
#define MB_TCP_REPORT_STATES 20
#define MB_TCP_REPORT_TEXTS 36
#define MB_TCP_REPORT_SIZE (36 + MB_TCP_MAX_ADDRS * MB_TCP_ADDR_TEXT)
#define MB_TCP_NONE 0xFFFFFFFFu

/* The overall status of a connect. */
#define MB_TCP_ST_CONNECTED 0
#define MB_TCP_ST_RESOLVE_FAILED 1
#define MB_TCP_ST_CONNECT_FAILED 2
#define MB_TCP_ST_TIMEOUT 3

/* What happened to one resolved address. */
#define MB_TCP_AS_NOT_TRIED 0
#define MB_TCP_AS_CONNECTED 1
#define MB_TCP_AS_FAILED 2
#define MB_TCP_AS_TIMED_OUT 3

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

/* --------------------------------------------------------------------------
 * Loop #83: resolving a host name.
 *
 * Before this loop, `mb_tcp_connect` only understood an IPv4 literal: it
 * called inet_pton(AF_INET) and gave up when that failed. So `ssh
 * user@example.com` did not work at all -- the name was never turned into an
 * address, so the connection never left the machine.
 *
 * OpenSSH's answer is in three places, and this follows them:
 *
 *   ssh.c:resolve_host       getaddrinfo(name, port, &hints) with
 *                            hints.ai_family = AF_UNSPEC and
 *                            hints.ai_socktype = SOCK_STREAM. It returns a
 *                            LIST of addresses, not one.
 *   sshconnect.c:ssh_connect_direct
 *                            "Loop through addresses for this host, and try
 *                            each one in sequence until the connection
 *                            succeeds." Each address gets its own socket and
 *                            its own timeout; a failure closes that socket
 *                            and moves on to the next address.
 *   misc.c:timeout_connect   a non-blocking connect, then a wait for the
 *                            socket, then a read of SO_ERROR -- where
 *                            optval != 0 means the connect failed.
 *
 * The Windows part is not portable, so it was measured rather than assumed.
 * (The measurement is .loop83/measure_socket.py; the numbers are in
 * AGENTS.md under "Loop #83".) Two of them change the design:
 *
 *   - A refused connect does NOT show up as "the socket became writable".
 *     On POSIX a failed connect makes poll/select report POLLOUT, and the
 *     reason is in SO_ERROR. On Windows the socket goes into the EXCEPT
 *     set instead. Waiting only for writability would therefore sit there
 *     until the deadline on every refused connection, and never learn that
 *     the connection had already failed.
 *
 *   - The refusal is not visible straight away. Measured here: a
 *     non-blocking connect to a closed port reports WSAEWOULDBLOCK at once,
 *     and for the next ~2.2 seconds select() reports the socket in NEITHER
 *     the write nor the except set, with SO_ERROR still 0. Then the except
 *     set lights up and SO_ERROR reads 10061 (WSAECONNREFUSED). A blocking
 *     connect to the same port takes about 2.0 seconds and returns
 *     WSAECONNREFUSED, so the two paths agree on the timing and differ only
 *     in who reports it.
 *
 * So the wait below watches the write set AND the except set, and it reads
 * SO_ERROR while it waits rather than only after select() returns: the
 * refusal can arrive either way, and the deadline has to be honoured in
 * both cases.
 * -------------------------------------------------------------------------- */

static void mb_put_u16(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
}

static void mb_put_u32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}

/* The numeric text of one address, the way OpenSSH prints it. */
static void mb_addr_text(const struct addrinfo *ai, unsigned char *slot) {
    char buf[NI_MAXHOST];

    memset(slot, 0, MB_TCP_ADDR_TEXT);
    if (getnameinfo(ai->ai_addr, (socklen_t)ai->ai_addrlen,
                    buf, sizeof(buf), NULL, 0, NI_NUMERICHOST) != 0) {
        buf[0] = '?';
        buf[1] = '\0';
    }
    strncpy((char *)slot, buf, MB_TCP_ADDR_TEXT - 1);
}

/* Try one address.
 *
 * Returns 0 when the connect worked (the socket comes back in *sock_out),
 * -1 when it failed (*err_out has the winsock error), and -2 when it ran
 * out of time.
 *
 * `timeout_ms` is the budget for THIS address, which is OpenSSH's
 * arrangement: ssh_connect_direct resets the timeout before every address
 * it tries. A timeout of 0 or less means "no deadline", and then the
 * connect blocks the way the operating system blocks it -- which is what
 * misc.c:timeout_connect does when its timeout is not positive. */
static int mb_connect_one(const struct addrinfo *ai, int timeout_ms,
                           SOCKET *sock_out, int *err_out) {
    SOCKET s;
    int one = 1;
    u_long nonblock;
    int rc;

    *sock_out = INVALID_SOCKET;
    *err_out = 0;
    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) {
        *err_out = WSAGetLastError();
        return -1;
    }
    if (timeout_ms <= 0) {
        rc = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        if (rc != 0) {
            *err_out = WSAGetLastError();
            closesocket(s);
            return -1;
        }
    } else {
        fd_set wfds;
        fd_set xfds;
        struct timeval tv;
        int optval = 0;
        int optlen = sizeof(optval);
        int waited = 0;

        nonblock = 1;
        if (ioctlsocket(s, FIONBIO, &nonblock) != 0) {
            *err_out = WSAGetLastError();
            closesocket(s);
            return -1;
        }
        rc = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        if (rc != 0) {
            int e = WSAGetLastError();
            if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAEINTR) {
                *err_out = e;
                closesocket(s);
                return -1;
            }
        }
        for (;;) {
            int slice = timeout_ms - waited;
            int ready;

            if (slice <= 0) {
                *err_out = WSAETIMEDOUT;
                closesocket(s);
                return -2;
            }
            if (slice > 100) {
                slice = 100;
            }
            FD_ZERO(&wfds);
            FD_SET(s, &wfds);
            FD_ZERO(&xfds);
            FD_SET(s, &xfds);
            tv.tv_sec = slice / 1000;
            tv.tv_usec = (slice % 1000) * 1000;
            ready = select(0, NULL, &wfds, &xfds, &tv);
            if (ready == SOCKET_ERROR) {
                *err_out = WSAGetLastError();
                closesocket(s);
                return -1;
            }
            if (ready == 0) {
                /* Nothing yet. The refusal may already be sitting in
                 * SO_ERROR even though select() did not report the socket,
                 * so read it before waiting again. */
                waited += slice;
                optval = 0;
                optlen = sizeof(optval);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&optval,
                               &optlen) == 0 && optval != 0) {
                    *err_out = optval;
                    closesocket(s);
                    return -1;
                }
                continue;
            }
            /* The socket was reported. SO_ERROR says whether the connect
             * actually worked: on Windows a refused connect arrives in the
             * except set and a successful one in the write set, and in both
             * cases the truth is in SO_ERROR. */
            optval = 0;
            optlen = sizeof(optval);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&optval,
                           &optlen) != 0) {
                *err_out = WSAGetLastError();
                closesocket(s);
                return -1;
            }
            if (optval != 0) {
                *err_out = optval;
                closesocket(s);
                return -1;
            }
            break;
        }
        /* Back to blocking: everything above this line reads and writes
         * the way a blocking socket does. */
        nonblock = 0;
        if (ioctlsocket(s, FIONBIO, &nonblock) != 0) {
            *err_out = WSAGetLastError();
            closesocket(s);
            return -1;
        }
    }
    /* SSH packets are small and strictly ordered; Nagle would add latency
     * for no throughput gain. */
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
    *sock_out = s;
    return 0;
}

/* Resolve a host name and connect to it, trying each address in turn.
 *
 * Returns the socket handle, or a negative error code. */
long long mb_tcp_connect_ex(const unsigned char *host, int host_len, int port,
                             int timeout_ms, unsigned char *report,
                             int report_cap) {
    char hostbuf[256];
    char strport[NI_MAXSERV];
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *ai;
    const struct addrinfo *addrs[MB_TCP_MAX_ADDRS];
    int n = 0;
    int k;
    int chosen = -1;
    int lastfail = -1;
    int timed_out = 0;
    unsigned int lasterr = 0;
    SOCKET s = INVALID_SOCKET;

    /* The report buffer has to be big enough for the WHOLE report, not just
     * its header: the address texts start at MB_TCP_REPORT_TEXTS and run to
     * the end of the buffer, so a caller that passed only the header's
     * length would have had the first address written past the end of it.
     * The MoonBit side always passes exactly MB_TCP_REPORT_SIZE. */
    if (report == NULL || report_cap < MB_TCP_REPORT_SIZE) {
        return MB_TCP_ERR_HOST;
    }
    memset(report, 0, (size_t)report_cap);
    if (mb_tcp_startup() != 0) {
        return MB_TCP_ERR_STARTUP;
    }
    if (host_len < 1 || host_len > 255) {
        return MB_TCP_ERR_HOST;
    }
    memcpy(hostbuf, host, (size_t)host_len);
    hostbuf[host_len] = '\0';

    snprintf(strport, sizeof(strport), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(hostbuf, strport, &hints, &res) != 0 || res == NULL) {
        mb_put_u32(report + MB_TCP_REPORT_STATUS, MB_TCP_ST_RESOLVE_FAILED);
        return MB_TCP_ERR_RESOLVE;
    }
    for (ai = res; ai != NULL && n < MB_TCP_MAX_ADDRS; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
            continue;
        }
        addrs[n] = ai;
        mb_addr_text(ai, report + MB_TCP_REPORT_TEXTS + n * MB_TCP_ADDR_TEXT);
        n++;
    }
    mb_put_u32(report + MB_TCP_REPORT_COUNT, (unsigned int)n);
    if (n == 0) {
        freeaddrinfo(res);
        mb_put_u32(report + MB_TCP_REPORT_STATUS, MB_TCP_ST_RESOLVE_FAILED);
        return MB_TCP_ERR_RESOLVE;
    }
    for (k = 0; k < n; k++) {
        int err = 0;
        int r = mb_connect_one(addrs[k], timeout_ms, &s, &err);

        if (r == 0) {
            chosen = k;
            report[MB_TCP_REPORT_STATES + k] = MB_TCP_AS_CONNECTED;
            break;
        }
        lasterr = (unsigned int)err;
        lastfail = k;
        if (r == -2) {
            report[MB_TCP_REPORT_STATES + k] = MB_TCP_AS_TIMED_OUT;
            timed_out = 1;
        } else {
            report[MB_TCP_REPORT_STATES + k] = MB_TCP_AS_FAILED;
        }
    }
    freeaddrinfo(res);
    mb_put_u32(report + MB_TCP_REPORT_CHOSEN,
               chosen < 0 ? MB_TCP_NONE : (unsigned int)chosen);
    mb_put_u32(report + MB_TCP_REPORT_LASTFAIL,
               lastfail < 0 ? MB_TCP_NONE : (unsigned int)lastfail);
    mb_put_u32(report + MB_TCP_REPORT_ERROR, lasterr);
    if (chosen >= 0) {
        mb_put_u32(report + MB_TCP_REPORT_STATUS, MB_TCP_ST_CONNECTED);
        return mb_tcp_track(s);
    }
    if (timed_out) {
        mb_put_u32(report + MB_TCP_REPORT_STATUS, MB_TCP_ST_TIMEOUT);
        return MB_TCP_ERR_CONNECT_TIMEOUT;
    }
    mb_put_u32(report + MB_TCP_REPORT_STATUS, MB_TCP_ST_CONNECT_FAILED);
    return MB_TCP_ERR_CONNECT;
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
 *   - MoonBit's #borrow annotation names one borrowed parameter per name in
 *     it, and a second borrowed pointer is possible -- `#borrow(a, b)` --
 *     but this repository had not used one until Loop #83. One buffer keeps
 *     the ABI to what is already proven to work (see mb_tcp_recv, which
 *     fills a buffer the caller reads back).
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
