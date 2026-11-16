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
	HANDLE err_from_child;	/* child writes as stderr, parent reads */
	int stdin_closed;
	int exited;
	int exit_code;
	ULONGLONG deadline_ms;	/* 0 = no deadline */
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
 * The two spawn entry points.
 *
 * `mb_subproc_spawn2` is defined below and `mb_subproc_spawn` calls it, so
 * the prototype comes first.
 */
long long mb_subproc_spawn2(const unsigned char *image, int image_len,
                             const unsigned char *args, int args_len,
                             int capture_err);

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
	return mb_subproc_spawn2(image, image_len, args, args_len, 0);
}

/*
 * Start `image` with `args`, its stdin and stdout on pipes, and -- when
 * `capture_err` is non-zero -- its stderr on a THIRD pipe instead of
 * inheriting ours.
 *
 * WHY A THIRD PIPE
 * ----------------
 * A server that runs a command has to report the command's stdout and the
 * command's stderr as two different things: in SSH they are different
 * channels (SSH_MSG_CHANNEL_DATA and SSH_MSG_CHANNEL_EXTENDED_DATA), and
 * merging them would make the two indistinguishable on the wire.
 *
 * The obvious way to get two files instead of two pipes -- putting
 * `> out 2> err` on the command line -- CANNOT work here, and the reason
 * is worth writing down because it looks so reasonable:
 *
 *   cmd.exe /c "<command>" > "out" 2> "err"
 *
 * cmd.exe's rule for the argument of /c is: if the first character is a
 * quote, strip it and remove the LAST quote character on the command line,
 * preserving any text after it.  With the redirections appended, the last
 * quote is the one closing "err", so the /c argument becomes
 *
 *   <command>" > "out" 2> "err"
 *
 * -- the redirections become part of the command, and `echo` prints them.
 * Measured: the whole tail came out on stdout.
 *
 * And the quote that the redirections would have cost is not cosmetic: the
 * real OpenSSH server runs `cmd.exe /c "<command>"`, and the trailing quote
 * that rule leaves behind is visible in the bytes the client receives
 * (`echo hello` comes back as `hello"`).  A command line with the
 * redirections inside the quotes produces `hello` instead -- a different
 * byte.  So the command line has to stay exactly `cmd.exe /c "<command>"`,
 * and the separation has to happen in the handles, which is what this
 * function does.
 */
long long
mb_subproc_spawn2(const unsigned char *image, int image_len,
                  const unsigned char *args, int args_len, int capture_err)
{
	MbSubproc *sp;
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE child_in = INVALID_HANDLE_VALUE, child_out = INVALID_HANDLE_VALUE;
	HANDLE child_err = INVALID_HANDLE_VALUE;
	WCHAR *cmdline = NULL;

	sp = (MbSubproc *)calloc(1, sizeof(*sp));
	if (sp == NULL)
		return MB_SUBPROC_INVALID;
	sp->process = INVALID_HANDLE_VALUE;
	sp->to_child = INVALID_HANDLE_VALUE;
	sp->from_child = INVALID_HANDLE_VALUE;
	sp->err_from_child = INVALID_HANDLE_VALUE;

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
	if (capture_err) {
		if (!CreatePipe(&sp->err_from_child, &child_err, &sa, 0))
			goto fail;
		if (!SetHandleInformation(sp->err_from_child, HANDLE_FLAG_INHERIT, 0))
			goto fail;
	}

	cmdline = mb_subproc_build_cmdline(image, image_len, args, args_len);
	if (cmdline == NULL)
		goto fail;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = child_in;
	si.hStdOutput = child_out;
	si.hStdError = capture_err ? child_err : GetStdHandle(STD_ERROR_HANDLE);

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
	if (child_err != INVALID_HANDLE_VALUE)
		CloseHandle(child_err);
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
		if (child_err != INVALID_HANDLE_VALUE)
			CloseHandle(child_err);
		if (cmdline != NULL)
			free(cmdline);
		if (sp->to_child != INVALID_HANDLE_VALUE)
			CloseHandle(sp->to_child);
		if (sp->from_child != INVALID_HANDLE_VALUE)
			CloseHandle(sp->from_child);
		if (sp->err_from_child != INVALID_HANDLE_VALUE)
			CloseHandle(sp->err_from_child);
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
 * The pipe a `which` selects: 0 is stdout, 1 is stderr.
 */
static HANDLE
mb_subproc_pipe(MbSubproc *sp, int which)
{
	if (which == 1)
		return sp->err_from_child;
	return sp->from_child;
}

/*
 * Read up to `n` bytes from the stdout (which=0) or the stderr (which=1)
 * pipe, into `buf + off`.
 *
 * Returns the number read, 0 at the end of that stream, -1 on error.
 *
 * The offset is there for the same reason it is on the write: the caller
 * accumulates into one buffer, and copying each chunk into a new array
 * would make the whole capture quadratic.
 */
long long
mb_subproc_read2(long long h, int which, unsigned char *buf, int off, int n)
{
	MbSubproc *sp = (MbSubproc *)(intptr_t)h;
	HANDLE pipe;
	DWORD got = 0;

	if (sp == NULL || buf == NULL || n <= 0 || off < 0)
		return -1;
	pipe = mb_subproc_pipe(sp, which);
	if (pipe == INVALID_HANDLE_VALUE)
		return 0;
	if (!ReadFile(pipe, buf + off, (DWORD)n, &got, NULL)) {
		if (GetLastError() == ERROR_BROKEN_PIPE)
			return 0;
		return -1;
	}
	return (long long)got;
}

/*
 * Is the pipe still open for writing?
 *
 * 1 for a live pipe, 0 for one whose writing end has been closed (the end of
 * that stream).  A pipe that has been closed is ALSO waitable -- waiting on
 * it returns immediately -- so it has to be taken out of the wait set, or
 * the reader spins.
 */
static int
mb_subproc_pipe_live(HANDLE pipe)
{
	DWORD avail = 0;

	if (pipe == INVALID_HANDLE_VALUE)
		return 0;
	if (!PeekNamedPipe(pipe, NULL, 0, NULL, &avail, NULL)) {
		if (GetLastError() == ERROR_BROKEN_PIPE)
			return 0;
		return 1;
	}
	return 1;
}

/*
 * Give the child a deadline: after `timeout_ms` milliseconds from now, the
 * waits start timing out even if the child is still alive.
 *
 * WHY A DEADLINE AND NOT A TIMEOUT PER WAIT
 * -----------------------------------------
 * A per-wait timeout bounds how long the parent waits for the NEXT thing,
 * not how long the child may run.  A command that writes a byte every
 * millisecond would never be interrupted by it, and a server that waits for
 * such a command waits forever.  The deadline is what says "this command
 * has had its turn".
 */
int
mb_subproc_set_timeout(long long h, int timeout_ms)
{
	MbSubproc *sp = (MbSubproc *)(intptr_t)h;

	if (sp == NULL)
		return -1;
	if (timeout_ms <= 0) {
		sp->deadline_ms = 0;
		return 0;
	}
	sp->deadline_ms = GetTickCount64() + (ULONGLONG)timeout_ms;
	return 0;
}

/*
 * Wait until one of the pipes has something to say, or the child exits, or
 * the timeout expires.
 *
 * Returns:
 *   1  the stdout pipe is ready
 *   2  the stderr pipe is ready
 *   3  both are ready
 *   0  the timeout expired (or the deadline passed)
 *  -1  the child has exited and both pipes are closed -- nothing more will
 *      ever arrive
 *
 * WHY THE WAIT IS HERE AND NOT IN THE CALLER
 * -------------------------------------------
 * Two pipes and one reader is a deadlock: a child that fills the stderr pipe
 * (64 KB) while the parent is blocked reading stdout stops writing, and the
 * parent never gets to the stderr it was waiting for.  So the parent must be
 * able to wait on BOTH at once, and it must not spin while it waits.  The
 * wait set is therefore the two live pipes plus the process itself: a pipe
 * becomes waitable when it has data, and the process becomes waitable when
 * it is gone.
 */
long long
mb_subproc_wait_any(long long h, int timeout_ms)
{
	MbSubproc *sp = (MbSubproc *)(intptr_t)h;
	HANDLE set[3];
	int n = 0;
	int idx_stdout = -1, idx_stderr = -1, idx_proc = -1;
	DWORD r;
	DWORD wait_ms;

	if (sp == NULL)
		return -1;
	if (sp->deadline_ms) {
		ULONGLONG now = GetTickCount64();
		if (now >= sp->deadline_ms)
			return 0;
		wait_ms = (DWORD)(sp->deadline_ms - now);
		if (timeout_ms >= 0 && (DWORD)timeout_ms < wait_ms)
			wait_ms = (DWORD)timeout_ms;
	} else {
		wait_ms = timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms;
	}
	for (;;) {
		n = 0;
		idx_stdout = idx_stderr = idx_proc = -1;
		if (mb_subproc_pipe_live(sp->from_child)) {
			set[n] = sp->from_child;
			idx_stdout = n;
			n++;
		}
		if (sp->err_from_child != INVALID_HANDLE_VALUE &&
		    mb_subproc_pipe_live(sp->err_from_child)) {
			set[n] = sp->err_from_child;
			idx_stderr = n;
			n++;
		}
		if (sp->process != INVALID_HANDLE_VALUE) {
			set[n] = sp->process;
			idx_proc = n;
			n++;
		}
		if (n == 0)
			return -1;
		r = WaitForMultipleObjects((DWORD)n, set, FALSE, wait_ms);
		if (r == WAIT_TIMEOUT)
			return 0;
		if (r == WAIT_FAILED)
			return -1;
		if ((int)(r - WAIT_OBJECT_0) == idx_proc) {
			/* The child is gone.  Its output may still be in the
			 * pipes, so the answer is "not done" until they are
			 * both closed as well. */
			if (!mb_subproc_pipe_live(sp->from_child) &&
			    (sp->err_from_child == INVALID_HANDLE_VALUE ||
			     !mb_subproc_pipe_live(sp->err_from_child)))
				return -1;
			continue;
		}
		{
			int ready = 0;
			if ((int)(r - WAIT_OBJECT_0) == idx_stdout)
				ready |= 1;
			if ((int)(r - WAIT_OBJECT_0) == idx_stderr)
				ready |= 2;
			return ready;
		}
	}
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
	if (sp->err_from_child != INVALID_HANDLE_VALUE)
		CloseHandle(sp->err_from_child);
	if (sp->process != INVALID_HANDLE_VALUE)
		CloseHandle(sp->process);
	free(sp);
	return 0;
}
