/*
 * agentpipe.c -- the Windows named pipe transport for the SSH agent.
 *
 * Loop #89.
 *
 * WHY A NAMED PIPE, AND NOT A SOCKET
 * ----------------------------------
 * The agent protocol is length-prefixed and unencrypted, so it can run
 * over anything that carries bytes.  On this platform the transport is
 * not a choice: the installed `ssh-add` refuses a TCP address without
 * even connecting --
 *
 *     $ SSH_AUTH_SOCK=127.0.0.1:1234 ssh-add -l
 *     Error connecting to agent: No such file or directory
 *
 * and it carries the literal string `SSH_AUTH_SOCK=\\.\\pipe\\openssh-ssh-agent`
 * in its binary.  The real client therefore talks to a NAMED PIPE, and
 * an agent that wants to be usable by the real client has to be one.
 *
 * THE SHAPE OF THE API
 * --------------------
 * A named pipe is not a stream socket: one HANDLE serves ONE client at
 * a time, and the next client has to wait for the pipe to be
 * disconnected first.  So the server side is:
 *
 *     create -> accept -> (read/write)* -> close
 *
 * and `accept` disconnects the previous client before it waits for the
 * next one.  The Windows OpenSSH agent does the same thing with one
 * worker per client; this one serves one client at a time, which is
 * enough for the tools that talk to it (`ssh-add` sends its request,
 * reads the reply and closes).
 *
 * The pipe is created in BYTE mode, which is what the agent protocol
 * expects: the framing is `u32 length` + `u32 type` + payload, and a
 * message-mode pipe would deliver the bytes in pieces.
 */

#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MB_AGENTPIPE_INVALID ((long long)-1)

/*
 * A name comes in as UTF-8 bytes and has to become UTF-16 for the
 * wide-character API.  The length is explicit because a MoonBit
 * String is not NUL-terminated.
 */
static WCHAR *
mb_agentpipe_widen(const unsigned char *name, int name_len)
{
	int n;
	WCHAR *out;

	if (name == NULL || name_len <= 0)
		return NULL;
	n = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)name, name_len, NULL, 0);
	if (n <= 0)
		return NULL;
	out = (WCHAR *)calloc((size_t)n + 1, sizeof(WCHAR));
	if (out == NULL)
		return NULL;
	if (MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)name, name_len, out, n) <= 0) {
		free(out);
		return NULL;
	}
	out[n] = 0;
	return out;
}

/*
 * Create ONE instance of the named pipe.
 *
 * `FILE_FLAG_FIRST_PIPE_INSTANCE` says that this must be the FIRST
 * instance of this name: a second create with the same name FAILS with
 * ERROR_ACCESS_DENIED instead of quietly making another instance.
 *
 * **Why that matters.**  A named pipe's name can have several instances,
 * and a client that connects to the name gets one of them -- the server
 * cannot tell which.  So two agents on one name would split their
 * clients between them, and each would answer half of them.  "One name,
 * one agent" is the only behaviour that can be reasoned about, and it is
 * also what a caller needs to be able to rely on: the second agent says
 * "the name is taken" instead of starting a second, half-working agent.
 *
 * The restriction is on CREATING an instance, not on accepting clients:
 * one instance still serves client after client, because
 * `DisconnectNamedPipe` in `mb_agentpipe_accept` hands it over.
 *
 * Returns the handle, or MB_AGENTPIPE_INVALID.  The handle is a
 * HANDLE, which is a pointer-sized value, so it travels as long long.
 */
long long
mb_agentpipe_server_create(const unsigned char *name, int name_len)
{
	WCHAR *wide;
	HANDLE h;

	wide = mb_agentpipe_widen(name, name_len);
	if (wide == NULL)
		return MB_AGENTPIPE_INVALID;
	h = CreateNamedPipeW(
		wide,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		65536, 65536, 0, NULL);
	free(wide);
	if (h == INVALID_HANDLE_VALUE)
		return MB_AGENTPIPE_INVALID;
	return (long long)(intptr_t)h;
}

/*
 * Wait for a client.
 *
 * The previous client is disconnected first: a pipe handle that is
 * still connected cannot take another one.  `ConnectNamedPipe` returns
 * FALSE with ERROR_PIPE_CONNECTED when a client connected between the
 * call and the wait, and that is a SUCCESS for us.
 *
 * Returns 0 on success and -1 on failure.
 */
int
mb_agentpipe_accept(long long handle)
{
	HANDLE h = (HANDLE)(intptr_t)handle;
	DWORD err;

	if (h == NULL || h == INVALID_HANDLE_VALUE)
		return -1;
	DisconnectNamedPipe(h);
	if (!ConnectNamedPipe(h, NULL)) {
		err = GetLastError();
		if (err != ERROR_PIPE_CONNECTED)
			return -1;
	}
	return 0;
}

/*
 * Connect to a named pipe as a client.
 *
 * The pipe has to exist already: CreateFile on a name that no server
 * has made fails with ERROR_FILE_NOT_FOUND, which is the "no agent"
 * answer.
 */
long long
mb_agentpipe_client_connect(const unsigned char *name, int name_len)
{
	WCHAR *wide;
	HANDLE h;
	DWORD mode = PIPE_READMODE_BYTE;

	wide = mb_agentpipe_widen(name, name_len);
	if (wide == NULL)
		return MB_AGENTPIPE_INVALID;
	h = CreateFileW(
		wide,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	free(wide);
	if (h == INVALID_HANDLE_VALUE)
		return MB_AGENTPIPE_INVALID;
	/* Byte mode, said by the client as well: the server's mode is a
	 * property of the connection, and the client is the one that
	 * reads. */
	SetNamedPipeHandleState(h, &mode, NULL, NULL);
	return (long long)(intptr_t)h;
}

/*
 * Read up to `n` bytes.  Returns the number of bytes read, 0 at the
 * end of the pipe, and -1 on failure.
 */
long long
mb_agentpipe_read(long long handle, unsigned char *buf, int n)
{
	HANDLE h = (HANDLE)(intptr_t)handle;
	DWORD got = 0;

	if (h == NULL || h == INVALID_HANDLE_VALUE || buf == NULL || n <= 0)
		return -1;
	if (!ReadFile(h, buf, (DWORD)n, &got, NULL))
		return -1;
	return (long long)got;
}

/*
 * Write up to `n` bytes starting at `off`.  Returns the number of
 * bytes written, or -1.
 *
 * The offset is part of the API because a pipe can take a short write,
 * and the caller has to be able to go round again with the rest.  It
 * is the same shape `mb_tcp_send` has.
 */
long long
mb_agentpipe_write(long long handle, const unsigned char *buf, int off, int n)
{
	HANDLE h = (HANDLE)(intptr_t)handle;
	DWORD put = 0;

	if (h == NULL || h == INVALID_HANDLE_VALUE || buf == NULL || off < 0 || n <= 0)
		return -1;
	if (!WriteFile(h, buf + off, (DWORD)n, &put, NULL))
		return -1;
	return (long long)put;
}

/*
 * Close a handle.  Returns 0 on success.
 */
int
mb_agentpipe_close(long long handle)
{
	HANDLE h = (HANDLE)(intptr_t)handle;

	if (h == NULL || h == INVALID_HANDLE_VALUE)
		return -1;
	CloseHandle(h);
	return 0;
}
