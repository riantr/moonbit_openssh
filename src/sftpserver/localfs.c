/* Loop #92: the SFTP server's filesystem, on Win32, wide.
 *
 * `src/sftpserver` is the server half of SFTP: it answers requests, and
 * this file is the half that touches the disk.  Everything here is
 * platform code for the same reason `src/scp/localfs.c` is: the RULES
 * (which reply, which status code, which sentence) live in MoonBit where
 * they can be tested against the real server's bytes, and this file
 * only does the I/O and reports failures.
 *
 * ## Why the W APIs and not the CRT
 *
 * A path crosses the boundary as UTF-8 bytes with an explicit length,
 * is widened once, and never comes back.  The narrow CRT entry points
 * take an ANSI path, which is lossy: a path is user data, it can contain
 * anything the filesystem allows, and turning it into the ANSI code
 * page fails on exactly the files a user cares about.  `src/scp`'s
 * `localfs.c` says the same thing at more length.
 *
 * ## The handle table
 *
 * The real server's handle is a SLOT, not a counter: two opens answer
 * `00000000` and `00000001`, and after the first is closed the next open
 * answers `00000000` again (measured, `.loop92/probe8_out.txt`).  So the
 * table below is a fixed array and the allocation finds the lowest free
 * slot -- and the slot index IS the handle the client sees.
 *
 * The table is 100 entries, which is the size OpenSSH uses.
 *
 * ## The sharing mode, and why it is not FILE_SHARE_WRITE
 *
 * Measured: with a READ handle open on a file, a later OPEN for writing
 * answers `4 Failure` -- the server's own refusal, not a protocol
 * error.  On Windows that refusal comes from the share mode, so the read
 * open must NOT share write access.  Two read opens of the same file
 * both succeed (measured), which is why the read open still shares read.
 *
 * ## The errors
 *
 * Each call returns either a value or a Win32 error code, and the
 * MoonBit side maps the code to a status.  The mapping is not guessed:
 * `src/sftpserver/fs.mbt` records which measurement each code comes
 * from.
 */

#include <windows.h>
#include <aclapi.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* `GetNamedSecurityInfoW` and friends live in advapi32, which the link
 * line does not carry by default. */
#pragma comment(lib, "advapi32.lib")

/* FILETIME is 100 ns ticks since 1601-01-01; Unix time is seconds since
 * 1970-01-01.  The difference is a constant, spelled out rather than
 * computed so a reader can check it:
 *
 *   369 years * 365.25 days * 86400 s * 10^7 = 116444736000000000
 */
#define MB_EPOCH_DIFF 116444736000000000ULL

/* The number of open handles.  OpenSSH's server uses 100. */
#define MB_MAX_HANDLES 100

/* The code GetLastError() left behind, for the calls that return only a
 * value and therefore cannot carry one. */
static int mb_last_error = 0;

/* One open handle: a file, or a directory being enumerated. */
struct mb_handle {
	HANDLE fh;			/* the file, for a file handle */
	int is_dir;			/* 1 for a directory handle */
	int in_use;
	DWORD access;
	HANDLE find;			/* the enumeration, for a directory */
	WIN32_FIND_DATAW find_data;
	int find_done;
	/* The directory's own path, for a directory handle.  It is what
	 * an entry's full path is built from, and the full path is what
	 * the ACL is read from. */
	wchar_t *path;
};
/* The handle table.  The slot index is the handle number the client
 * sees, so the allocation must find the LOWEST free slot. */
static struct mb_handle mb_handles[MB_MAX_HANDLES];

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

/* The attributes of one path, or 0 when it cannot be read. */
static int mb_attributes(const wchar_t *w) {
	DWORD attrs;
	if (w == NULL) {
		return 0;
	}
	attrs = GetFileAttributesW(w);
	if (attrs == INVALID_FILE_ATTRIBUTES) {
		mb_last_error = (int)GetLastError();
		return 0;
	}
	return (int)attrs;
}

/* 0 missing, 1 a regular file, 2 a directory, -1 something else. */
int32_t mb_sftp_kind(const char *path, int32_t len) {
	wchar_t *w = mb_wide(path, len);
	int attrs;
	int32_t out;
	if (w == NULL) {
		return -1;
	}
	attrs = mb_attributes(w);
	free(w);
	if (attrs == 0) {
		return 0;
	}
	if ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
		out = 2;
	} else {
		out = 1;
	}
	return out;
}

/* Whether the SID is one of the two that stand for "everybody".
 *
 * Measured: the permission word's "other" field follows the rights that
 * EVERYBODY has -- an ACE for `Everyone` or for `Authenticated Users`.
 * An ACE for `BUILTIN\Users` does not move it, even though the user is a
 * member of that group, because the field is about the class of accounts
 * that is neither the owner nor the file's group.
 *
 * `.loop92/probe_acl2.py` measured the whole table:
 *
 *   grant                          the "other" field
 *   Everyone:(M)                   7   (rwx)
 *   Everyone:(GR,GE)               5   (r-x)
 *   Authenticated Users:(M)         7
 *   Authenticated Users:(GR,GE)     5
 *   BUILTIN\Users:(M)               0
 *   BUILTIN\Users:(RX)              0
 *   nothing                         0
 */
static int mb_is_everybody_sid(PSID sid) {
	BYTE everyone[SECURITY_MAX_SID_SIZE];
	BYTE authed[SECURITY_MAX_SID_SIZE];
	DWORD n = SECURITY_MAX_SID_SIZE;
	if (CreateWellKnownSid(WinWorldSid, NULL, everyone, &n)) {
		if (EqualSid(sid, everyone)) {
			return 1;
		}
	}
	n = SECURITY_MAX_SID_SIZE;
	if (CreateWellKnownSid(WinAuthenticatedUserSid, NULL, authed, &n)) {
		if (EqualSid(sid, authed)) {
			return 1;
		}
	}
	return 0;
}

/* The "other" bits of the mode word: 4 for read, 2 for write, 1 for
 * execute, and 0 when the path has no readable ACL.
 *
 * The rights are the GENERIC ones, because that is what the measurements
 * used: an ACE granted `(RX)` -- the specific rights -- moved nothing,
 * while `(GR,GE)` moved the read and execute bits.
 */
static int32_t mb_other_bits_w(const wchar_t *w) {
	PACL dacl = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	ACL_SIZE_INFORMATION asi;
	DWORD rc;
	DWORD i;
	int bits = 0;
	rc = GetNamedSecurityInfoW(w, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
	    NULL, NULL, &dacl, NULL, &sd);
	if (rc != ERROR_SUCCESS || dacl == NULL) {
		if (sd != NULL) {
			LocalFree(sd);
		}
		return 0;
	}
	if (GetAclInformation(dacl, &asi, sizeof(asi), AclSizeInformation)) {
		for (i = 0; i < asi.AceCount; i++) {
			ACCESS_ALLOWED_ACE *ace = NULL;
			if (!GetAce(dacl, i, (LPVOID *)&ace) || ace == NULL) {
				continue;
			}
			if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) {
				continue;
			}
			/* An INHERIT_ONLY ACE grants nothing to the object
			 * itself -- it only tells the children what to
			 * inherit. */
			if (ace->Header.AceFlags & INHERIT_ONLY_ACE) {
				continue;
			}
			if (!mb_is_everybody_sid(&ace->SidStart)) {
				continue;
			}
			if (ace->Mask & FILE_GENERIC_READ) {
				bits |= 4;
			}
			if (ace->Mask & FILE_GENERIC_WRITE) {
				bits |= 2;
			}
			if (ace->Mask & FILE_GENERIC_EXECUTE) {
				bits |= 1;
			}
		}
	}
	LocalFree(sd);
	return (int32_t)bits;
}

/* The "other" bits of the mode word, for a path in UTF-8. */
int32_t mb_sftp_other_bits(const char *path, int32_t len) {
	wchar_t *w;
	int32_t bits;
	w = mb_wide(path, len);
	if (w == NULL) {
		return 0;
	}
	bits = mb_other_bits_w(w);
	free(w);
	return bits;
}

/* The "other" bits of the mode word, for an entry of an open directory.
 *
 * The entry's own path is the directory's path and the entry's name, and
 * it is that path whose ACL is read -- an entry can have an ACL of its
 * own, different from the directory's. */
static int32_t mb_sftp_other_bits_for_name(
    struct mb_handle *h, const wchar_t *name) {
	size_t dl;
	size_t nl;
	wchar_t *full;
	int32_t bits;
	if (h == NULL || h->path == NULL || name == NULL) {
		return 0;
	}
	dl = wcslen(h->path);
	nl = wcslen(name);
	full = (wchar_t *)malloc((dl + nl + 2) * sizeof(wchar_t));
	if (full == NULL) {
		return 0;
	}
	memcpy(full, h->path, dl * sizeof(wchar_t));
	full[dl] = L'\\';
	memcpy(full + dl + 1, name, nl * sizeof(wchar_t));
	full[dl + 1 + nl] = L'\0';
	bits = mb_other_bits_w(full);
	free(full);
	return bits;
}

/* Size in bytes, or -1 when it cannot be read.
 *
 * For a DIRECTORY this is the filesystem's own number, and it is not a
 * constant: measured with the real server, a directory with 0, 1, 16 and
 * 120 entries answers 0, 0, 4096 and 24576 -- the NTFS index, in 4096
 * byte clusters.  So the number is whatever the platform says, and a
 * server that answered a fixed 4096 would be right for one directory and
 * wrong for every other one. */
int64_t mb_sftp_size(const char *path, int32_t len) {
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
int64_t mb_sftp_mtime(const char *path, int32_t len) {
	wchar_t *w = mb_wide(path, len);
	WIN32_FILE_ATTRIBUTE_DATA data;
	if (w == NULL) {
		return -1;
	}
	if (!GetFileAttributesExW(w, GetFileExInfoStandard, &data)) {
		mb_last_error = (int)GetLastError();
		free(w);
		return -1;
	}
	free(w);
	return mb_filetime_secs(&data.ftLastWriteTime);
}

/* Last-access time in seconds since the epoch, or -1.
 *
 * The real server reports atime and mtime SEPARATELY and correctly: a
 * file whose mtime was moved 30 days back while its atime was left
 * alone reports `(now, now-30d)`.  So this is the access time, not the
 * write time twice. */
int64_t mb_sftp_atime(const char *path, int32_t len) {
	wchar_t *w = mb_wide(path, len);
	WIN32_FILE_ATTRIBUTE_DATA data;
	if (w == NULL) {
		return -1;
	}
	if (!GetFileAttributesExW(w, GetFileExInfoStandard, &data)) {
		mb_last_error = (int)GetLastError();
		free(w);
		return -1;
	}
	free(w);
	return mb_filetime_secs(&data.ftLastAccessTime);
}

/* 1 when the file is read-only, 0 when it is not, -1 when it is
 * missing. */
int32_t mb_sftp_readonly(const char *path, int32_t len) {
	wchar_t *w = mb_wide(path, len);
	int attrs;
	if (w == NULL) {
		return -1;
	}
	attrs = mb_attributes(w);
	free(w);
	if (attrs == 0) {
		return -1;
	}
	return (attrs & FILE_ATTRIBUTE_READONLY) != 0 ? 1 : 0;
}

/* The lowest free slot in the handle table, or -1 when the table is
 * full.  The slot index is the handle the client sees. */
static int mb_handle_alloc(void) {
	int i;
	for (i = 0; i < MB_MAX_HANDLES; i++) {
		if (!mb_handles[i].in_use) {
			return i;
		}
	}
	return -1;
}

static struct mb_handle *mb_handle_at(int32_t n) {
	if (n < 0 || n >= MB_MAX_HANDLES) {
		return NULL;
	}
	if (!mb_handles[n].in_use) {
		return NULL;
	}
	return &mb_handles[n];
}

/* Open a file.
 *
 * The flags are the protocol's: 1 read, 2 write, 8 create.  A request
 * with neither read nor write is a READ open -- measured: OPEN with
 * flags 0 answers a handle, and a READ on that handle returns the file's
 * bytes.
 *
 * The share mode is the measured one: the read open does not share
 * write access, which is what makes a later write open fail the way the
 * real server's fails.
 *
 * Returns the handle, or -1 with the Win32 code parked. */
int32_t mb_sftp_open(const char *path, int32_t len, int32_t flags) {
	wchar_t *w;
	HANDLE h;
	int slot;
	DWORD access;
	DWORD share;
	DWORD creation;
	if ((flags & 3) == 0) {
		access = GENERIC_READ;
	} else if ((flags & 3) == 1) {
		access = GENERIC_READ;
	} else if ((flags & 3) == 2) {
		access = GENERIC_WRITE;
	} else {
		access = GENERIC_READ | GENERIC_WRITE;
	}
	if (access == GENERIC_READ) {
		share = FILE_SHARE_READ;
	} else {
		share = FILE_SHARE_READ;
	}	if ((flags & 8) != 0) {
		creation = OPEN_ALWAYS;
	} else {
		creation = OPEN_EXISTING;
	}
	w = mb_wide(path, len);
	if (w == NULL) {
		mb_last_error = ERROR_INVALID_NAME;
		return -1;
	}
	slot = mb_handle_alloc();
	if (slot < 0) {
		free(w);
		mb_last_error = ERROR_TOO_MANY_OPEN_FILES;
		return -1;
	}
	h = CreateFileW(w, access, share, NULL, creation, FILE_ATTRIBUTE_NORMAL,
	    NULL);
	free(w);
	if (h == INVALID_HANDLE_VALUE) {
		mb_last_error = (int)GetLastError();
		return -1;
	}
	mb_handles[slot].fh = h;
	mb_handles[slot].is_dir = 0;
	mb_handles[slot].in_use = 1;
	mb_handles[slot].access = access;
	mb_handles[slot].find = INVALID_HANDLE_VALUE;
	mb_handles[slot].find_done = 0;
	return (int32_t)slot;
}

/* Open a directory for listing. */
int32_t mb_sftp_opendir(const char *path, int32_t len) {
	wchar_t *w;
	wchar_t *pattern;
	size_t wl;
	int slot;
	HANDLE find;
	WIN32_FIND_DATAW first;
	w = mb_wide(path, len);
	if (w == NULL) {
		mb_last_error = ERROR_INVALID_NAME;
		return -1;
	}
	wl = wcslen(w);
	pattern = (wchar_t *)malloc((wl + 3) * sizeof(wchar_t));
	if (pattern == NULL) {
		free(w);
		mb_last_error = ERROR_NOT_ENOUGH_MEMORY;
		return -1;
	}
	wcscpy(pattern, w);
	if (wl > 0 && pattern[wl - 1] != L'\\' && pattern[wl - 1] != L'/') {
		wcscat(pattern, L"\\");
	}
	wcscat(pattern, L"*");
	/* The FIRST entry comes back in `first`, and the slot it will live
	 * in is not known yet -- so it is copied in afterwards rather than
	 * written into the table before the slot exists. */
	find = FindFirstFileW(pattern, &first);
	free(pattern);
	if (find == INVALID_HANDLE_VALUE) {
		mb_last_error = (int)GetLastError();
		free(w);
		return -1;
	}
	slot = mb_handle_alloc();
	if (slot < 0) {
		FindClose(find);
		free(w);
		mb_last_error = ERROR_TOO_MANY_OPEN_FILES;
		return -1;
	}
	mb_handles[slot].fh = INVALID_HANDLE_VALUE;
	mb_handles[slot].is_dir = 1;
	mb_handles[slot].in_use = 1;
	mb_handles[slot].access = 0;
	mb_handles[slot].find = find;
	mb_handles[slot].find_done = 0;
	/* The directory's path is kept, because an entry's full path is
	 * built from it and the full path is what the ACL is read from. */
	mb_handles[slot].path = (wchar_t *)malloc((wl + 1) * sizeof(wchar_t));
	if (mb_handles[slot].path != NULL) {
		memcpy(mb_handles[slot].path, w, (wl + 1) * sizeof(wchar_t));
	}
	free(w);
	memcpy(&mb_handles[slot].find_data, &first, sizeof(first));
	return (int32_t)slot;
}

/* The next entry of an open directory.
 *
 * Returns the length of the name written into `namebuf`, or -1 at the
 * end of the listing, or -2 when the buffer was too small, or -3 on
 * error.
 *
 * The entry's own attributes come back in `attrs`, as five 64-bit
 * words: size, mtime, atime, is_dir, is_readonly.  They come from the
 * enumeration's own data rather than from a second lookup of the path,
 * because the enumeration already HAS them and a second lookup would be
 * a chance for the two to disagree.
 *
 * The order is the filesystem's own, NOT a sort: the real server's
 * listing of `a b.txt`, `a-b.txt`, `a.txt`, `a0.txt`, `a_b.txt`,
 * `a~.txt`, `B.txt` is the order NTFS's name index holds them in, and
 * sorting would put `B.txt` first.
 *
 * `.` and `..` are skipped: the real server's listing of a directory
 * with ten files had ten entries, not twelve. */
int32_t mb_sftp_readdir(
    int32_t handle,
    char *namebuf,
    int32_t cap,
    int64_t *attrs) {
	struct mb_handle *h = mb_handle_at(handle);
	WIN32_FIND_DATAW data;
	int need;
	if (h == NULL || !h->is_dir) {
		mb_last_error = ERROR_INVALID_HANDLE;
		return -3;
	}
	for (;;) {
		if (h->find_done) {
			return -1;
		}
		/* The entry in hand is the one FindFirstFileW or the last
		 * FindNextFileW produced; it is copied out BEFORE the
		 * next call overwrites it. */
		memcpy(&data, &h->find_data, sizeof(data));
		if (!FindNextFileW(h->find, &h->find_data)) {
			h->find_done = 1;
		}
		if (wcscmp(data.cFileName, L".") == 0 ||
		    wcscmp(data.cFileName, L"..") == 0) {
			if (h->find_done) {
				return -1;
			}
			continue;
		}
		need = WideCharToMultiByte(CP_UTF8, 0, data.cFileName, -1, NULL, 0,
		    NULL, NULL);
		if (need <= 0) {
			mb_last_error = (int)GetLastError();
			return -3;
		}
		if (need > cap) {
			return -2;
		}
		WideCharToMultiByte(CP_UTF8, 0, data.cFileName, -1, namebuf, need,
		    NULL, NULL);
		{
			ULARGE_INTEGER size;
			size.LowPart = data.nFileSizeLow;
			size.HighPart = data.nFileSizeHigh;
			/* The size here is the ENUMERATION's own size, which
			 * for a directory is 0 -- and that is what the real
			 * server reports in a listing, even though a STAT of
			 * the same directory answers 4096.  The two are
			 * different questions and the real server answers
			 * them differently. */
			attrs[0] = (int64_t)size.QuadPart;
			attrs[1] = mb_filetime_secs(&data.ftLastWriteTime);
			attrs[2] = mb_filetime_secs(&data.ftLastAccessTime);
			attrs[3] =
			    (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
			attrs[4] =
			    (data.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? 1 : 0;
			/* The ACL-derived "other" bits of the mode word.  The
			 * name is the only thing that names the entry, so
			 * the ACL is read from the name's own path. */
			attrs[5] = (int64_t)mb_sftp_other_bits_for_name(h, data.cFileName);
		}
		return (int32_t)need;
	}
}

/* Read at most `cap` bytes at `offset`.  Returns the number read, or
 * -1. */
int64_t mb_sftp_read(int32_t handle, int64_t offset, char *buf, int64_t cap) {
	struct mb_handle *h = mb_handle_at(handle);
	LARGE_INTEGER pos;
	DWORD got = 0;
	if (h == NULL || h->is_dir) {
		mb_last_error = ERROR_INVALID_HANDLE;
		return -1;
	}
	pos.QuadPart = offset;
	if (!SetFilePointerEx(h->fh, pos, NULL, FILE_BEGIN)) {
		mb_last_error = (int)GetLastError();
		return -1;
	}
	if (cap <= 0) {
		return 0;
	}
	if (!ReadFile(h->fh, buf, (DWORD)cap, &got, NULL)) {
		mb_last_error = (int)GetLastError();
		return -1;
	}
	return (int64_t)got;
}

/* Write `n` bytes at `offset`.  Returns 0, or the Win32 error code. */
int32_t mb_sftp_write(int32_t handle, int64_t offset, const char *buf,
    int64_t n) {
	struct mb_handle *h = mb_handle_at(handle);
	LARGE_INTEGER pos;
	DWORD put = 0;
	if (h == NULL || h->is_dir) {
		return ERROR_INVALID_HANDLE;
	}
	pos.QuadPart = offset;
	if (!SetFilePointerEx(h->fh, pos, NULL, FILE_BEGIN)) {
		return (int32_t)GetLastError();
	}
	if (n <= 0) {
		return 0;
	}
	if (!WriteFile(h->fh, buf, (DWORD)n, &put, NULL)) {
		return (int32_t)GetLastError();
	}
	return 0;
}

/* Truncate an open file to `size`. */
int32_t mb_sftp_truncate(int32_t handle, int64_t size) {
	struct mb_handle *h = mb_handle_at(handle);
	LARGE_INTEGER pos;
	if (h == NULL || h->is_dir) {
		return ERROR_INVALID_HANDLE;
	}
	pos.QuadPart = size;
	if (!SetFilePointerEx(h->fh, pos, NULL, FILE_BEGIN)) {
		return (int32_t)GetLastError();
	}
	if (!SetEndOfFile(h->fh)) {
		return (int32_t)GetLastError();
	}
	return 0;
}

/* Close a handle. */
int32_t mb_sftp_close(int32_t handle) {
	struct mb_handle *h = mb_handle_at(handle);
	if (h == NULL) {
		return ERROR_INVALID_HANDLE;
	}
	if (h->is_dir) {
		if (h->find != INVALID_HANDLE_VALUE) {
			FindClose(h->find);
		}
	} else {
		CloseHandle(h->fh);
	}
	h->in_use = 0;
	h->find = INVALID_HANDLE_VALUE;
	h->fh = INVALID_HANDLE_VALUE;
	if (h->path != NULL) {
		free(h->path);
		h->path = NULL;
	}
	return 0;
}

/* Set the modification and access times of a path. */
int32_t mb_sftp_setmtime(const char *path, int32_t len, int64_t secs) {
	wchar_t *w = mb_wide(path, len);
	HANDLE h;
	FILETIME ft;
	if (w == NULL) {
		return ERROR_INVALID_NAME;
	}
	h = CreateFileW(w, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
	    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	free(w);
	if (h == INVALID_HANDLE_VALUE) {
		return (int32_t)GetLastError();
	}
	ft = mb_secs_filetime(secs);
	if (!SetFileTime(h, &ft, &ft, NULL)) {
		int32_t err = (int32_t)GetLastError();
		CloseHandle(h);
		return err;
	}
	CloseHandle(h);
	return 0;
}

/* Create one directory. */
int32_t mb_sftp_mkdir(const char *path, int32_t len) {
	wchar_t *w = mb_wide(path, len);
	if (w == NULL) {
		return ERROR_INVALID_NAME;
	}
	if (CreateDirectoryW(w, NULL)) {
		free(w);
		return 0;
	}
	{
		int32_t err = (int32_t)GetLastError();
		free(w);
		return err;
	}
}

/* Remove a directory. */
int32_t mb_sftp_rmdir(const char *path, int32_t len) {
	wchar_t *w = mb_wide(path, len);
	if (w == NULL) {
		return ERROR_INVALID_NAME;
	}
	if (RemoveDirectoryW(w)) {
		free(w);
		return 0;
	}
	{
		int32_t err = (int32_t)GetLastError();
		free(w);
		return err;
	}
}

/* Remove a file. */
int32_t mb_sftp_remove(const char *path, int32_t len) {
	wchar_t *w = mb_wide(path, len);
	if (w == NULL) {
		return ERROR_INVALID_NAME;
	}
	if (DeleteFileW(w)) {
		free(w);
		return 0;
	}
	{
		int32_t err = (int32_t)GetLastError();
		free(w);
		return err;
	}
}

/* Rename a path.  The target must not exist: the real server answers
 * `4 Failure` when it does, and `MoveFileEx` without REPLACE_EXISTING
 * fails the same way. */
int32_t mb_sftp_rename(const char *from, int32_t fromlen, const char *to,
    int32_t tolen) {
	wchar_t *wf = mb_wide(from, fromlen);
	wchar_t *wt = mb_wide(to, tolen);
	if (wf == NULL || wt == NULL) {
		free(wf);
		free(wt);
		return ERROR_INVALID_NAME;
	}
	if (MoveFileExW(wf, wt, 0)) {
		free(wf);
		free(wt);
		return 0;
	}
	{
		int32_t err = (int32_t)GetLastError();
		free(wf);
		free(wt);
		return err;
	}
}

/* Rename a path, replacing the target if it exists.
 *
 * This is what `posix-rename@openssh.com` is: the extension the real
 * server advertises, and the one that makes an overwrite possible where
 * plain RENAME refuses. */
int32_t mb_sftp_rename_replace(const char *from, int32_t fromlen,
    const char *to, int32_t tolen) {
	wchar_t *wf = mb_wide(from, fromlen);
	wchar_t *wt = mb_wide(to, tolen);
	if (wf == NULL || wt == NULL) {
		free(wf);
		free(wt);
		return ERROR_INVALID_NAME;
	}
	if (MoveFileExW(wf, wt, MOVEFILE_REPLACE_EXISTING)) {
		free(wf);
		free(wt);
		return 0;
	}
	{
		int32_t err = (int32_t)GetLastError();
		free(wf);
		free(wt);
		return err;
	}
}

/* The absolute form of a path, in the spelling the server uses.
 *
 * Measured: the real server answers REALPATH with `/C:/Users/...` --
 * the drive letter is prefixed with a SLASH and the separators are
 * forward ones.  A Windows path with backslashes is a different string,
 * and a client that compares them byte for byte sees the difference.
 *
 * `..` is resolved, and the path need not exist: the real server
 * answers a path for a file that is not there.
 *
 * Returns the length written, or -1. */
int32_t mb_sftp_realpath(const char *path, int32_t len, char *buf, int32_t cap) {
	wchar_t *w = mb_wide(path, len);
	wchar_t *full;
	DWORD need;
	char *p;
	int32_t i;
	int32_t out;
	if (w == NULL) {
		return -1;
	}
	need = GetFullPathNameW(w, 0, NULL, NULL);
	if (need == 0) {
		mb_last_error = (int)GetLastError();
		free(w);
		return -1;
	}
	full = (wchar_t *)malloc((need + 1) * sizeof(wchar_t));
	if (full == NULL) {
		free(w);
		mb_last_error = ERROR_NOT_ENOUGH_MEMORY;
		return -1;
	}
	need = GetFullPathNameW(w, need + 1, full, NULL);
	free(w);
	if (need == 0) {
		free(full);
		mb_last_error = (int)GetLastError();
		return -1;
	}
	/* `GetFullPathNameW` gives `C:\Users\...`; the server's spelling
	 * is `/C:/Users/...`, so the separators become forward ones and a
	 * slash goes in front of the drive letter. */
	{
		int32_t n = (int32_t)need;
		int32_t wlen = (int32_t)wcslen(full);
		int32_t k;
		int32_t slash = 1;
		for (k = 0; k < wlen; k++) {
			if (full[k] == L'\\') {
				full[k] = L'/';
			}
		}
		out = 0;
		if (slash) {
			if (out + 1 >= cap) {
				free(full);
				return -2;
			}
			buf[out++] = '/';
		}
		for (k = 0; k < wlen; k++) {
			if (out + 4 >= cap) {
				free(full);
				return -2;
			}
			if (full[k] < 0x80) {
				buf[out++] = (char)full[k];
			} else {
				/* A non-ASCII character is put out as UTF-8
				 * by asking the wide-to-multibyte
				 * conversion for one character at a
				 * time. */
				char one[8];
				int m = WideCharToMultiByte(CP_UTF8, 0, &full[k], 1,
				    one, (int)sizeof(one), NULL, NULL);
				int j;
				if (m <= 0) {
					free(full);
					return -1;
				}
				for (j = 0; j < m; j++) {
					if (out + 1 >= cap) {
						free(full);
						return -2;
					}
					buf[out++] = one[j];
				}
			}
		}
		p = buf;
		(void)p;
	}
	free(full);
	return out;
}

/* The code left behind by the last call that could only return a
 * value. */
int32_t mb_sftp_last_error(void) {
	return (int32_t)mb_last_error;
}

/* The current time, in seconds since the epoch. */
int64_t mb_sftp_now(void) {
	return (int64_t)time(NULL);
}

/* The local offset from UTC, in seconds, at a given time.
 *
 * The date column of the longname is LOCAL time -- the recordings show
 * `14:18` for a file modified at the time the probe ran, and this
 * machine is not at UTC -- so the conversion has to know the offset, and
 * the offset changes with daylight saving, so it is a function of the
 * time rather than a constant. */
int32_t mb_sftp_utc_offset(int64_t epoch) {
	time_t t = (time_t)epoch;
	struct tm lt;
	struct tm gt;
	int64_t off;
	if (localtime_s(&lt, &t) != 0 || gmtime_s(&gt, &t) != 0) {
		return 0;
	}
	off = ((int64_t)lt.tm_hour - (int64_t)gt.tm_hour) * 3600 +
	    ((int64_t)lt.tm_min - (int64_t)gt.tm_min) * 60 +
	    ((int64_t)lt.tm_sec - (int64_t)gt.tm_sec);
	if (lt.tm_yday != gt.tm_yday) {
		off += (lt.tm_yday > gt.tm_yday) ? 86400 : -86400;
	}
	return (int32_t)off;
}

/* Write raw bytes to stdout (stream 0) or stderr (stream 1).
 *
 * The driver speaks SFTP over its own standard input and output, and
 * the protocol is binary: a text-translating writer would change the
 * bytes. */
int32_t mb_sftp_emit(int32_t stream, const char *buf, int32_t len) {
	HANDLE h;
	int32_t put = 0;
	if (stream == 0) {
		h = GetStdHandle(STD_OUTPUT_HANDLE);
	} else {
		h = GetStdHandle(STD_ERROR_HANDLE);
	}
	if (h == NULL || h == INVALID_HANDLE_VALUE) {
		return ERROR_INVALID_HANDLE;
	}
	while (put < len) {
		DWORD wrote = 0;
		if (!WriteFile(h, buf + put, (DWORD)(len - put), &wrote, NULL)) {
			return (int32_t)GetLastError();
		}
		if (wrote == 0) {
			return ERROR_WRITE_FAULT;
		}
		put += (int32_t)wrote;
	}
	return 0;
}

/* Read raw bytes from standard input.
 *
 * Returns the number of bytes read, 0 at end of input, or -1 on
 * error.  The bytes are read as they are: the protocol frames them
 * itself, and a reader that waited for a newline would corrupt every
 * frame that contained one. */
int32_t mb_sftp_read_stdin(char *buf, int32_t cap) {
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	DWORD got = 0;
	if (h == NULL || h == INVALID_HANDLE_VALUE) {
		return -1;
	}
	if (!ReadFile(h, buf, (DWORD)cap, &got, NULL)) {
		return -1;
	}
	return (int32_t)got;
}
