/* Loop #90: the local half of `scp`, on Win32, wide.
 *
 * `scp` copies between this machine and a server, so it needs a local
 * filesystem: stat, read, write, mkdir, list, and (for -p) set a time.
 * The rest of the engine is written against six function values
 * (`engine.mbt`), which is what lets the recursion be unit tested with no
 * filesystem at all; this file is the only platform-specific piece.
 *
 * ## Why the W APIs and not `_stat64` / `fopen`
 *
 * The narrow CRT entry points take an ANSI path, and this repository has
 * already been bitten by the code page once (`ssh` printing a GBK message
 * in Loop #90's own session notes).  A path is user data: it comes from
 * `argv`, it can contain anything the filesystem allows, and turning it
 * into the ANSI code page is a lossy conversion that fails on exactly the
 * files a user cares about.  So every path here crosses as **UTF-8 bytes
 * with an explicit length** (MoonBit's `Bytes` is not NUL-terminated),
 * is widened once by `mb_wide`, and never comes back.
 *
 * ## Why the error text is NOT in this file
 *
 * Each function that can fail returns the raw `GetLastError()` code (or
 * -1 with the code parked for `mb_localfs_last_error`).  The mapping from
 * code to the sentence `scp` prints -- `No such file or directory`,
 * `Permission denied` -- lives in `localfs.mbt`, because it is a rule: it
 * can be unit tested on all four targets there, and a mutation can be
 * aimed at it without touching C.
 *
 * ## What is deliberately absent
 *
 * No symlink handling, no ACLs, no attributes beyond size and mtime.
 * `scp` needs six operations and this file provides exactly six; anything
 * else would be code with no caller and no test.
 */

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* FILETIME is 100 ns ticks since 1601-01-01; Unix time is seconds since
 * 1970-01-01.  The difference is a constant, and it is spelled out rather
 * than computed so a reader can check it:
 *
 *   369 years * 365.25 days * 86400 s * 10^7 = 116444736000000000
 */
#define MB_EPOCH_DIFF 116444736000000000ULL

/* The code GetLastError() left behind, for the paths that return only a
 * byte count and therefore cannot carry it. */
static int mb_last_error = 0;

/* Widen a UTF-8 path of `len` bytes into a fresh NUL-terminated wide
 * string.  Returns NULL on failure (the caller frees with free()). */
static wchar_t *mb_wide(const char *path, int len) {
    wchar_t *out;
    int n;
    if (path == NULL || len < 0) {
        return NULL;
    }
    n = MultiByteToWideChar(CP_UTF8, 0, path, len, NULL, 0);
    if (n <= 0) {
        return NULL;
    }
    out = (wchar_t *)malloc((size_t)(n + 1) * sizeof(wchar_t));
    if (out == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, path, len, out, n) <= 0) {
        free(out);
        return NULL;
    }
    out[n] = L'\0';
    return out;
}

/* One FILETIME as seconds since the Unix epoch. */
static long long mb_filetime_secs(const FILETIME *ft) {
    ULARGE_INTEGER t;
    t.LowPart = ft->dwLowDateTime;
    t.HighPart = ft->dwHighDateTime;
    if (t.QuadPart < MB_EPOCH_DIFF) {
        return 0;
    }
    return (long long)((t.QuadPart - MB_EPOCH_DIFF) / 10000000ULL);
}

/* The Unix epoch as a FILETIME. */
static FILETIME mb_secs_filetime(long long secs) {
    ULARGE_INTEGER t;
    FILETIME ft;
    t.QuadPart = (unsigned long long)secs * 10000000ULL + MB_EPOCH_DIFF;
    ft.dwLowDateTime = t.LowPart;
    ft.dwHighDateTime = t.HighPart;
    return ft;
}

/* 0 missing, 1 a regular file, 2 a directory, -1 something else. */
int32_t mb_localfs_kind(const char *path, int32_t len) {
    wchar_t *w = mb_wide(path, len);
    DWORD attrs;
    int32_t out;
    if (w == NULL) {
        return -1;
    }
    attrs = GetFileAttributesW(w);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        mb_last_error = (int)GetLastError();
        free(w);
        return 0;
    }
    if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        out = 2;
    } else {
        out = 1;
    }
    free(w);
    return out;
}

/* Size in bytes, or -1 when it cannot be read. */
int64_t mb_localfs_size(const char *path, int32_t len) {
    wchar_t *w = mb_wide(path, len);
    WIN32_FILE_ATTRIBUTE_DATA data;
    ULARGE_INTEGER size;
    if (w == NULL) {
        return -1;
    }
    if (!GetFileAttributesExW(w, GetFileExInfoStandard, &data)) {
        mb_last_error = (int)GetLastError();
        free(w);
        return -1;
    }
    free(w);
    size.LowPart = data.nFileSizeLow;
    size.HighPart = data.nFileSizeHigh;
    return (int64_t)size.QuadPart;
}

/* Last-write time in seconds since the epoch, or -1. */
int64_t mb_localfs_mtime(const char *path, int32_t len) {
    wchar_t *w = mb_wide(path, len);
    WIN32_FILE_ATTRIBUTE_DATA data;
    long long out;
    if (w == NULL) {
        return -1;
    }
    if (!GetFileAttributesExW(w, GetFileExInfoStandard, &data)) {
        mb_last_error = (int)GetLastError();
        free(w);
        return -1;
    }
    free(w);
    out = mb_filetime_secs(&data.ftLastWriteTime);
    return (int64_t)out;
}

/* Fill `buf` with the whole file, up to `cap` bytes.
 *
 * Returns the number of bytes read, or -1.  A file that grew after the
 * caller sized the buffer is read up to `cap` and no further: `scp` is
 * copying a snapshot, and a caller that wants the rest can call again. */
int64_t mb_localfs_read(const char *path, int32_t len, char *buf,
                        int64_t cap) {
    wchar_t *w = mb_wide(path, len);
    HANDLE h;
    int64_t got = 0;
    if (w == NULL) {
        return -1;
    }
    h = CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) {
        mb_last_error = (int)GetLastError();
        return -1;
    }
    while (got < cap) {
        DWORD want = (DWORD)((cap - got) > 0x7FFFFFFF ? 0x7FFFFFFF : (cap - got));
        DWORD read = 0;
        if (!ReadFile(h, buf + got, want, &read, NULL)) {
            mb_last_error = (int)GetLastError();
            CloseHandle(h);
            return -1;
        }
        if (read == 0) {
            break;
        }
        got += (int64_t)read;
    }
    CloseHandle(h);
    return got;
}

/* Write `n` bytes, creating or truncating the file.
 *
 * Returns 0, or the Win32 error code that stopped it. */
int32_t mb_localfs_write(const char *path, int32_t len, const char *buf,
                         int64_t n) {
    wchar_t *w = mb_wide(path, len);
    HANDLE h;
    int64_t put = 0;
    if (w == NULL) {
        return (int32_t)ERROR_INVALID_NAME;
    }
    h = CreateFileW(w, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) {
        return (int32_t)GetLastError();
    }
    while (put < n) {
        DWORD want = (DWORD)((n - put) > 0x7FFFFFFF ? 0x7FFFFFFF : (n - put));
        DWORD wrote = 0;
        if (!WriteFile(h, buf + put, want, &wrote, NULL)) {
            int32_t err = (int32_t)GetLastError();
            CloseHandle(h);
            return err;
        }
        if (wrote == 0) {
            CloseHandle(h);
            return (int32_t)ERROR_WRITE_FAULT;
        }
        put += (int64_t)wrote;
    }
    CloseHandle(h);
    return 0;
}

/* Create one directory.  0 created, 1 already there, else the error. */
int32_t mb_localfs_mkdir(const char *path, int32_t len) {
    wchar_t *w = mb_wide(path, len);
    if (w == NULL) {
        return (int32_t)ERROR_INVALID_NAME;
    }
    if (CreateDirectoryW(w, NULL)) {
        free(w);
        return 0;
    }
    {
        int32_t err = (int32_t)GetLastError();
        free(w);
        if (err == ERROR_ALREADY_EXISTS) {
            return 1;
        }
        return err;
    }
}

/* The names directly inside a directory, NUL separated, into `buf`.
 *
 * Returns the number of bytes written.  -2 means the buffer was too small
 * and the caller should retry bigger; -1 means the listing failed and
 * `mb_localfs_last_error` has the code.
 *
 * `.` and `..` are skipped: the walker above would recurse forever on
 * them and no caller wants them. */
int64_t mb_localfs_list(const char *path, int32_t len, char *buf, int64_t cap) {
    wchar_t *w = mb_wide(path, len);
    wchar_t *pattern;
    size_t wl;
    HANDLE find;
    WIN32_FIND_DATAW data;
    int64_t used = 0;
    if (w == NULL) {
        return -1;
    }
    wl = wcslen(w);
    pattern = (wchar_t *)malloc((wl + 3) * sizeof(wchar_t));
    if (pattern == NULL) {
        free(w);
        return -1;
    }
    wcscpy(pattern, w);
    if (wl > 0 && pattern[wl - 1] != L'\\' && pattern[wl - 1] != L'/') {
        wcscat(pattern, L"\\");
    }
    wcscat(pattern, L"*");
    find = FindFirstFileW(pattern, &data);
    free(pattern);
    free(w);
    if (find == INVALID_HANDLE_VALUE) {
        mb_last_error = (int)GetLastError();
        return -1;
    }
    for (;;) {
        if (wcscmp(data.cFileName, L".") != 0 &&
            wcscmp(data.cFileName, L"..") != 0) {
            int need = WideCharToMultiByte(CP_UTF8, 0, data.cFileName, -1, NULL,
                                           0, NULL, NULL);
            if (need <= 0) {
                FindClose(find);
                mb_last_error = (int)GetLastError();
                return -1;
            }
            if (used + (int64_t)need > cap) {
                FindClose(find);
                return -2;
            }
            WideCharToMultiByte(CP_UTF8, 0, data.cFileName, -1, buf + used, need,
                                NULL, NULL);
            used += (int64_t)need;
        }
        if (!FindNextFileW(find, &data)) {
            DWORD err = GetLastError();
            FindClose(find);
            if (err != ERROR_NO_MORE_FILES) {
                mb_last_error = (int)err;
                return -1;
            }
            break;
        }
    }
    return used;
}

/* Set the last-write and last-access time to the same instant.
 *
 * Returns 0 or the Win32 error code. */
int32_t mb_localfs_set_mtime(const char *path, int32_t len, int64_t secs) {
    wchar_t *w = mb_wide(path, len);
    HANDLE h;
    FILETIME ft;
    if (w == NULL) {
        return (int32_t)ERROR_INVALID_NAME;
    }
    /* FILE_WRITE_ATTRIBUTES is enough to move a time and nothing else,
     * which is the smallest right a copy that only preserves times needs. */
    h = CreateFileW(w, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) {
        return (int32_t)GetLastError();
    }
    ft = mb_secs_filetime(secs);
    if (!SetFileTime(h, NULL, &ft, &ft)) {
        int32_t err = (int32_t)GetLastError();
        CloseHandle(h);
        return err;
    }
    CloseHandle(h);
    return 0;
}

/* The code left behind by the last call that could only return a count. */
int32_t mb_localfs_last_error(void) {
    return (int32_t)mb_last_error;
}

/* Write raw bytes to stdout (stream 0) or stderr (stream 1).
 *
 * ## Why not `println`
 *
 * Measured on this toolchain: `eprintln("A\nB")` emits `A\r\nB\r\n` --
 * the whole string is text-translated, and a trailing newline is added.
 * `scp`'s own output is not uniform: every line ends `\r\n` EXCEPT the
 * `-P` refusal, whose embedded newline stays a bare `\n` (`.loop90/
 * DESIGN.md` section 5 captured it byte for byte as `bad port "0"\n\r\n`,
 * which is what a raw `write()` of the message plus a translated trailing
 * newline produces).  A text-translating writer cannot express that, so
 * the driver builds the bytes and this function writes them unchanged.
 *
 * Returns 0, or the Win32 error code. */
int32_t mb_scp_emit(int32_t stream, const char *buf, int32_t len) {
    HANDLE h;
    int32_t put = 0;
    if (stream == 0) {
        h = GetStdHandle(STD_OUTPUT_HANDLE);
    } else {
        h = GetStdHandle(STD_ERROR_HANDLE);
    }
    if (h == NULL || h == INVALID_HANDLE_VALUE) {
        return (int32_t)ERROR_INVALID_HANDLE;
    }
    while (put < len) {
        DWORD wrote = 0;
        if (!WriteFile(h, buf + put, (DWORD)(len - put), &wrote, NULL)) {
            return (int32_t)GetLastError();
        }
        if (wrote == 0) {
            return (int32_t)ERROR_WRITE_FAULT;
        }
        put += (int32_t)wrote;
    }
    return 0;
}
