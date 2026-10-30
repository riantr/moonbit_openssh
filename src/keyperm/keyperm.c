/* Loop #85: making a private key file private, on Windows.
 *
 * A file created on Windows inherits the ACL of the directory it was
 * created in.  In an ordinary user directory that ACL includes
 * "Authenticated Users" with read access, so a private key written there
 * is readable by every other process on the machine -- and OpenSSH
 * refuses to use it, saying "Permissions for '...' are too open.  It is
 * required that your private key files are NOT accessible by others."
 *
 * The fix is to replace the file's ACL with one that grants the OWNER
 * alone, and to protect that ACL from inheriting the directory's
 * permissions back.
 *
 * The DACL is built from an SDDL string rather than by hand:
 *
 *   D:P(A;;FA;;;<owner sid>)
 *
 *   D    -- a DACL (as opposed to an SACL)
 *   P    -- PROTECTED: the ACL does not inherit from the parent
 *   A    -- an ACCESS_ALLOWED ACE
 *   FA   -- FILE_ALL_ACCESS
 *   ;;;  -- the three empty fields are the ACE type, the object type
 *           and the inherited-object type
 *   <sid> -- the file's owner
 *
 * SDDL is used because the alternative -- building the ACL_REVISION /
 * ACCESS_ALLOWED_ACE bytes by hand -- is exactly the kind of thing that
 * reads past the end of a SID and crashes, and a crash in a function
 * whose job is to protect a secret is a bad way to spend an afternoon.
 *
 * **The owner SID comes from GetNamedSecurityInfoW's OWNER OUTPUT
 * PARAMETER, not from GetSecurityDescriptorOwner.**  The two are not
 * interchangeable: GetNamedSecurityInfoW hands back a SELF-RELATIVE
 * security descriptor, and the owner pointer inside a self-relative
 * descriptor is an offset into the descriptor rather than a separate
 * allocation -- so reading it through the wrong accessor and then
 * passing it to an API that frees it corrupts the heap.  The output
 * parameter is the API's own, correctly-scoped pointer.
 *
 * The path is passed with an explicit length because a MoonBit `Bytes`
 * is not NUL-terminated, and every one of these Windows APIs wants a
 * NUL-terminated string.  The bytes are copied into a local buffer that
 * is terminated here.
 *
 * A note on what this does NOT do: it does not protect the file from an
 * administrator, and nothing can.  It protects it from the other users
 * of the machine, which is what the file's mode is about.
 *
 * A note on failure: the caller is told.  A key file that was written
 * and could not be protected is a key file that must not be reported as
 * done, so this returns a negative stage code rather than pretending it
 * worked.  The stage codes are:
 *
 *   -1  the path could not be widened
 *   -2  the file's owner could not be read
 *   -3  the owner SID could not be turned into a string
 *   -4  the SDDL string could not be converted
 *   -5  the new ACL could not be installed
 */

#include <windows.h>
#include <sddl.h>
#include <aclapi.h>

#pragma comment(lib, "advapi32.lib")

/* PROTECTED_DACL_INHERIT.
 *
 * The Windows SDK header that declares it is not always reachable from a
 * build that only has the um/ include path, so the value is spelled out
 * here.  It is a SECURITY_INFORMATION flag, and the value is fixed by
 * the API:
 *
 *   PROTECTED_DACL_INHERIT    0x80000000
 *   UNPROTECTED_DACL_INHERIT  0x20000000
 */
#ifndef PROTECTED_DACL_INHERIT
#define PROTECTED_DACL_INHERIT 0x80000000
#endif

/* Restrict `path` (given as `path_len` bytes, not NUL-terminated) to its
 * owner.
 *
 * Returns 0 on success and a negative stage code on failure.
 */
int mb_keyperm_protect(const char *path, int path_len) {
    PSECURITY_DESCRIPTOR file_sd = NULL;
    PSECURITY_DESCRIPTOR new_sd = NULL;
    PACL dacl = NULL;
    BOOL dacl_present = FALSE;
    DWORD dacl_size = 0;
    LPWSTR wpath = NULL;
    LPWSTR sid_string = NULL;
    LPWSTR sddl = NULL;
    PSID owner_sid = NULL;
    int wlen = 0;
    DWORD rc;
    int result = -5;

    if (path == NULL || path_len < 0) {
        return -1;
    }

    /* A wide, NUL-terminated copy of the path. */
    wlen = MultiByteToWideChar(CP_UTF8, 0, path, path_len, NULL, 0);
    if (wlen <= 0) {
        return -1;
    }
    wpath = (LPWSTR)malloc((size_t)(wlen + 1) * sizeof(wchar_t));
    if (wpath == NULL) {
        return -1;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, path, path_len, wpath, wlen) <= 0) {
        free(wpath);
        return -1;
    }
    wpath[wlen] = L'\0';

    /* The file's owner SID, straight from the API's own output
     * parameter. */
    rc = GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT,
                               OWNER_SECURITY_INFORMATION, &owner_sid,
                               NULL, NULL, NULL, &file_sd);
    if (rc != ERROR_SUCCESS || owner_sid == NULL) {
        result = -2;
        goto done;
    }

    /* The owner SID as a string, so it can go into the SDDL. */
    if (!ConvertSidToStringSidW(owner_sid, &sid_string)) {
        result = -3;
        goto done;
    }

    /* "D:P(A;;FA;;;<sid>)" */
    {
        size_t sid_len = wcslen(sid_string);
        size_t sddl_len = 64 + sid_len;
        sddl = (LPWSTR)malloc((sddl_len + 1) * sizeof(wchar_t));
        if (sddl == NULL) {
            result = -3;
            goto done;
        }
        wcscpy(sddl, L"D:P(A;;FA;;;");
        wcscat(sddl, sid_string);
        wcscat(sddl, L")");
    }

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &new_sd, NULL)) {
        result = -4;
        goto done;
    }

    /* Install it.
     *
     * SetFileSecurity takes the WHOLE security descriptor, and the one
     * ConvertStringSecurityDescriptorToSecurityDescriptorW produced is
     * exactly that.  This avoids the self-relative-versus-absolute
     * business entirely: the descriptor is handed over as it is, and
     * the API reads the DACL out of it.
     *
     * The PROTECTED flag is not a SECURITY_INFORMATION flag here -- it
     * lives in the descriptor's control flags, and the "P" in the SDDL
     * string is what sets it.  So the SDDL's "D:P" does the protecting
     * and the API does the installing.
     */
    if (!SetFileSecurityW(wpath, DACL_SECURITY_INFORMATION, new_sd)) {
        result = -5;
        goto done;
    }
    result = 0;

 done:
    if (sddl != NULL) {
        free(sddl);
    }
    if (sid_string != NULL) {
        LocalFree(sid_string);
    }
    if (new_sd != NULL) {
        LocalFree(new_sd);
    }
    if (file_sd != NULL) {
        LocalFree(file_sd);
    }
    if (wpath != NULL) {
        free(wpath);
    }
    return result;
}
