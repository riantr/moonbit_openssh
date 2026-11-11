/*
 * subproc.c -- run a child process with its stdin and stdout on pipes.
 *
 * Loop #90.
 *
 * WHY THIS EXISTS
 * ---------------
 * `scp -D <path>` is a testing hook built into the real tool: instead of
 * connecting to a host it runs the named program and speaks SFTP over
 * that program's stdin and stdout.  Measured on this machine
 * (`.loop90/DESIGN.md` section 3), it works with a path that contains a
 * space and it needs no network, no sshd and no key material -- which
 * makes it the cheapest honest comparison available for `scp`.
 *
 * To drive the same bed, an implementation has to be able to do the same
 * thing: start a program, write its stdin, read its stdout, and learn its
 * exit status.  That is what this file adds.
 *
 * THE THREE DETAILS THAT ARE EASY TO GET WRONG
 * --------------------------------------------
 * 1. `lpApplicationName` is given explicitly, and the command line is
 *    built as `"<image>" <args>`.  Passing the raw path as the command
 *    line would split `C:\Program Files\OpenSSH-Win64\sftp-server.exe`
 *    at the space -- and the real tool does not, which is why the bed
 *    works at all.
 * 2. The parent must close the ends it does not use, or the child never
 *    sees EOF on stdin and `read` never sees EOF on stdout.  Both are
 *    closed before the spawn returns.
 * 3. `SetHandleInformation(..., HANDLE_FLAG_INHERIT, 0)` on the parent's
 *    own ends.  Without it a grandchild can inherit them and keep the
 *    pipe open after the child exits, and `read` blocks forever.
 *
 * The handle returned is a pointer to the struct below, not a Windows
 * HANDLE: a process needs three handle values plus state, so one opaque
 * pointer is what crosses the ABI.
 */

#include <windows.h>
#include <stdlib.h>
#include <string.h>

#define MB_SUBPROC_INVALID ((long long)-1)

typedef struct {
	HANDLE process;
	HANDLE to_child;	/* parent writes, child reads as stdin */
	HANDLE from_child;	/* child writes as stdout, parent reads */
	int stdin_closed;
	int exited;
	int exit_code;
} MbSubproc;

/*
 * UTF-8 bytes -> a NUL-terminated wide string, or NULL.
 *
 * The MoonBit side passes bytes plus a length rather than a String,
 * because a MoonBit String carries no terminator and the wide-character
 * API reads until one.
 */
static WCHAR *
mb_subproc_widen(const unsigned char *s, int n)
{
	WCHAR *out;
	int need;

	if (s == NULL || n < 0)
		return NULL;
	need = MultiByteToWideChar(CP_UTF8, 0, (const char *)s, n, NULL, 0);
	if (need <= 0)
		return NULL;
	out = (WCHAR *)malloc(sizeof(WCHAR) * (need + 1));
	if (out == NULL)
		return NULL;
	if (MultiByteToWideChar(CP_UTF8, 0, (const char *)s, n, out, need) != need) {
		free(out);
		return NULL;
	}
	out[need] = L'\0';
	return out;
}

/*
 * `"<image>" <args>` as a wide string.
 *
 * Quoting the image is what makes a path with a space survive; args are
 * appended verbatim because the caller is the one that knows whether they
 * need quoting.
 */
static WCHAR *
mb_subproc_build_cmdline(const unsigned char *image, int image_len,
                         const unsigned char *args, int args_len)
{
	WCHAR *wimage, *wargs, *out;
	size_t need;

	wimage = mb_subproc_widen(image, image_len);
	if (wimage == NULL)
		return NULL;
	wargs = NULL;
	if (args != NULL && args_len > 0) {
		wargs = mb_subproc_widen(args, args_len);
		if (wargs == NULL) {
			free(wimage);
			return NULL;
		}
	}
	need = wcslen(wimage) + 8 + (wargs ? wcslen(wargs) : 0);
	out = (WCHAR *)malloc(sizeof(WCHAR) * need);
	if (out != NULL) {
		wcscpy(out, L"\"");
		wcscat(out, wimage);
		wcscat(out, L"\"");
		if (wargs != NULL) {
			wcscat(out, L" ");
			wcscat(out, wargs);
		}
	}
	free(wimage);
	free(wargs);
	return out;
}

/*
 * Start `image` with `args`, its stdin and stdout on pipes.
 *
 * Returns an opaque handle, or -1.  The child's stderr is inherited
 * deliberately: `sftp-server.exe` reports a configuration problem there
 * and nowhere else, and swallowing it would turn "the server refused"
 * into "the protocol hung".
 */
long long
mb_subproc_spawn(const unsigned char *image, int image_len,
                 const unsigned char *args, int args_len)
{
	MbSubproc *sp;
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE child_in = INVALID_HANDLE_VALUE, child_out = INVALID_HANDLE_VALUE;
	WCHAR *cmdline = NULL;

	sp = (MbSubproc *)calloc(1, sizeof(*sp));
	if (sp == NULL)
		return MB_SUBPROC_INVALID;
	sp->process = INVALID_HANDLE_VALUE;
	sp->to_child = INVALID_HANDLE_VALUE;
	sp->from_child = INVALID_HANDLE_VALUE;

	memset(&sa, 0, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	if (!CreatePipe(&child_in, &sp->to_child, &sa, 0))
		goto fail;
	/* The parent's writing end must NOT be inherited: a grandchild
	 * holding it keeps the child's stdin open after the parent closes
	 * it, and the child then waits for input that will never come. */
	if (!SetHandleInformation(sp->to_child, HANDLE_FLAG_INHERIT, 0))
		goto fail;
	if (!CreatePipe(&sp->from_child, &child_out, &sa, 0))
		goto fail;
	if (!SetHandleInformation(sp->from_child, HANDLE_FLAG_INHERIT, 0))
		goto fail;

	cmdline = mb_subproc_build_cmdline(image, image_len, args, args_len);
	if (cmdline == NULL)
		goto fail;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = child_in;
	si.hStdOutput = child_out;
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

	/*
	 * `lpApplicationName` is NULL on purpose, and this is measured, not
	 * stylistic.  With a non-NULL application name Win32 does NOT search
	 * `PATH`, so `proc_spawn("cmd.exe", ...)` failed with "could not be
	 * started" until this changed -- and the test that caught it is
	 * `subproc_native_test.mbt`.  With NULL, the first token of the
	 * command line names the program, `PATH` is searched the way the
	 * shell would, and the quoting this file already does keeps a path
	 * with a space in it in one piece.
	 */
	memset(&pi, 0, sizeof(pi));
	if (!CreateProcessW(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL,
	                    &si, &pi)) {
		goto fail;
	}

	/* The child's ends belong to the child now. */
	CloseHandle(child_in);
	CloseHandle(child_out);
	free(cmdline);
	sp->process = pi.hProcess;
	CloseHandle(pi.hThread);
	return (long long)(intptr_t)sp;

fail:
	{
		DWORD saved = GetLastError();
		if (child_in != INVALID_HANDLE_VALUE)
			CloseHandle(child_in);
		if (child_out != INVALID_HANDLE_VALUE)
			CloseHandle(child_out);
		if (cmdline != NULL)
			free(cmdline);
		if (sp->to_child != INVALID_HANDLE_VALUE)
			CloseHandle(sp->to_child);
		if (sp->from_child != INVALID_HANDLE_VALUE)
			CloseHandle(sp->from_child);
		free(sp);
		SetLastError(saved);
		return MB_SUBPROC_INVALID;
	}
}

/*
 * Write `n` bytes from `buf + off`.  Returns the number written, or -1.
 *
 * A short write is a real possibility on a pipe, so this loops until the
 * caller's bytes are all out or the write fails -- the SFTP framing above
 * it assumes the whole packet was delivered.
 */
long long
mb_subproc_write(long long h, const unsigned char *buf, int off, int n)
{
	MbSubproc *sp = (MbSubproc *)(intptr_t)h;
	int done = 0;

	if (sp == NULL || buf == NULL || n <= 0 || off < 0)
		return -1;
	if (sp->stdin_closed || sp->to_child == INVALID_HANDLE_VALUE)
		return -1;
	while (done < n) {
		DWORD put = 0;
		if (!WriteFile(sp->to_child, buf + off + done, (DWORD)(n - done),
		               &put, NULL))
			return -1;
		if (put == 0)
			return -1;
		done += (int)put;
	}
	return done;
}

/*
 * Read up to `n` bytes into `buf`.
 *
 * Returns the number read, 0 at end of output, -1 on error.  Blocking:
 * the caller is the SFTP driver, which has just asked a question and is
 * waiting for the answer.
 */
long long
mb_subproc_read(long long h, unsigned char *buf, int n)
{
	MbSubproc *sp = (MbSubproc *)(intptr_t)h;
	DWORD got = 0;

	if (sp == NULL || buf == NULL || n <= 0)
		return -1;
	if (sp->from_child == INVALID_HANDLE_VALUE)
		return 0;
	if (!ReadFile(sp->from_child, buf, (DWORD)n, &got, NULL)) {
		if (GetLastError() == ERROR_BROKEN_PIPE)
			return 0;
		return -1;
	}
	return (long long)got;
}

/*
 * Close the writing end, so the child sees end of input.
 */
int
mb_subproc_close_stdin(long long h)
{
	MbSubproc *sp = (MbSubproc *)(intptr_t)h;

	if (sp == NULL || sp->stdin_closed)
		return -1;
	if (sp->to_child != INVALID_HANDLE_VALUE) {
		CloseHandle(sp->to_child);
		sp->to_child = INVALID_HANDLE_VALUE;
	}
	sp->stdin_closed = 1;
	return 0;
}

/*
 * Wait for the child and return its exit status, or -1.
 *
 * Cached: a second call answers the same thing rather than waiting on a
 * process handle that has already been reaped.
 */
int
mb_subproc_wait(long long h)
{
	MbSubproc *sp = (MbSubproc *)(intptr_t)h;
	DWORD code = 0;

	if (sp == NULL || sp->process == INVALID_HANDLE_VALUE)
		return -1;
	if (sp->exited)
		return sp->exit_code;
	if (WaitForSingleObject(sp->process, INFINITE) != WAIT_OBJECT_0)
		return -1;
	if (!GetExitCodeProcess(sp->process, &code))
		return -1;
	sp->exited = 1;
	sp->exit_code = (int)code;
	return sp->exit_code;
}

/*
 * Terminate the child.  Idempotent; a failure is not interesting because
 * the only caller is a cleanup path that is already unwinding.
 */
int
mb_subproc_kill(long long h)
{
	MbSubproc *sp = (MbSubproc *)(intptr_t)h;

	if (sp == NULL || sp->process == INVALID_HANDLE_VALUE || sp->exited)
		return 0;
	TerminateProcess(sp->process, 1);
	return 0;
}

/*
 * Release every handle.  Does not wait: the caller decides whether the
 * exit status mattered.
 */
int
mb_subproc_close(long long h)
{
	MbSubproc *sp = (MbSubproc *)(intptr_t)h;

	if (sp == NULL)
		return 0;
	if (sp->to_child != INVALID_HANDLE_VALUE)
		CloseHandle(sp->to_child);
	if (sp->from_child != INVALID_HANDLE_VALUE)
		CloseHandle(sp->from_child);
	if (sp->process != INVALID_HANDLE_VALUE)
		CloseHandle(sp->process);
	free(sp);
	return 0;
}
