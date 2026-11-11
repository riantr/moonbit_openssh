///| Win32 error codes, spelled the way `scp` spells them.
///
/// ## Why this table is in a MoonBit file and not in the C one
///
/// The sentences are part of `scp`'s observable output -- they appear
/// inside the tool's own messages (`stat local "x": No such file or
/// directory`, measured) -- so they are a **rule**, and rules in this
/// repository live where a unit test can pin them and a mutation can be
/// aimed at them.  `localfs.c` therefore returns the raw code and this
/// file decides what it means.
///
/// ## Why the spelling is not invented
///
/// These are the strings the Microsoft C runtime's `strerror` produces on
/// an English install, which is what the real tool prints on this machine
/// (`.loop90/probe_scp_D6.py` scenario 13 captured
/// `open local "local/nodir/out.txt": No such file or directory`).  The
/// repository has already met the localised version of this problem -- a
/// GBK message out of `ssh` in this very session -- so the gate that
/// compares our bytes against the real tool's runs with the same English
/// locale, and a machine in another locale would disagree in exactly this
/// spot.
///
/// ## The codes
///
/// Only the ones a copy can actually reach are listed.  A code that is
/// not here becomes `Unknown error`, which is what the C runtime says for
/// a code it has no text for -- not a silence, and not a crash.

///|
/// `ERROR_FILE_NOT_FOUND` = 2 and `ERROR_PATH_NOT_FOUND` = 3.
///
/// Both map to `ENOENT`'s text, and both are reachable: a missing file is
/// 2, and a destination whose parent directory is missing is 3 (measured:
/// `local/nodir/out.txt`).
const WIN32_FILE_NOT_FOUND : Int32 = 2

///|
/// `ERROR_ACCESS_DENIED` = 5.
const WIN32_ACCESS_DENIED : Int32 = 5

///|
/// `ERROR_ALREADY_EXISTS` = 183.
const WIN32_ALREADY_EXISTS : Int32 = 183

///|
/// `ERROR_DIRECTORY` = 267 -- "the directory name is invalid".
const WIN32_NOT_A_DIRECTORY : Int32 = 267

///|
/// `ERROR_DISK_FULL` = 112.
const WIN32_DISK_FULL : Int32 = 112

///|
/// `ERROR_WRITE_FAULT` = 29.
const WIN32_WRITE_FAULT : Int32 = 29

///|
/// `ERROR_INVALID_NAME` = 123.
const WIN32_INVALID_NAME : Int32 = 123

///|
/// `ERROR_SHARING_VIOLATION` = 32.
const WIN32_SHARING_VIOLATION : Int32 = 32

///|
/// A Win32 error code as the sentence `scp` would print for it.
pub fn win32_reason(code : Int32) -> String {
  if code == WIN32_FILE_NOT_FOUND || code == 3 {
    reason_no_such_file()
  } else if code == WIN32_ACCESS_DENIED {
    reason_permission_denied()
  } else if code == WIN32_ALREADY_EXISTS {
    "File exists"
  } else if code == WIN32_NOT_A_DIRECTORY {
    reason_not_a_directory()
  } else if code == WIN32_DISK_FULL {
    "No space left on device"
  } else if code == WIN32_WRITE_FAULT {
    "Input/output error"
  } else if code == WIN32_INVALID_NAME {
    "Invalid argument"
  } else if code == WIN32_SHARING_VIOLATION {
    "Resource temporarily unavailable"
  } else {
    "Unknown error"
  }
}
