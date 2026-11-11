///| Loop #92: the server's `longname` -- the `ls -l` line it builds.
///
/// This is the fiddliest thing the server does, and every number in it
/// was MEASURED rather than derived, because the layout is not the one a
/// reader would guess.  The measurements are in
/// `.loop92/probe2_out.txt` (the column arithmetic checked by
/// `.loop92/longname_check.py`) and `.loop92/probe11_out.txt`.
///
/// ## The measured layout
///
/// ```
/// -rw-******    1 -        -              13 Nov 11 13:52 a.txt
/// drwx******    1 -        -               0 Nov 11 13:52 dir
/// ```
///
/// Column by column, with every width counted from the recorded bytes:
///
///   * the MODE STRING: ten characters.  A file is `-rw-`, a read-only file
///     is `-r--`, a directory is `drwx` -- so the first four characters
///     carry the type and the OWNER's three permission bits.
///   * the six ASTERISKS: the group and other columns, which Windows
///     cannot fill in.  They are LITERAL asterisks the real server sends,
///     not a placeholder this code substitutes.
///   * four spaces, then the link count (`1`).
///   * a space, the user (`-`), eight spaces, the group (`-`).
///   * eight spaces, then the SIZE, printed as `%8llu` -- right-aligned in
///     eight columns.
///   * a space, the DATE (twelve characters), a space, the NAME.
///
/// The eight spaces between the group column and the size are the gap the
/// `ls -l` layout leaves for a group column wide enough to hold a name; the
/// real server fills it with spaces, and a layout that used one space there
/// would put the size seven columns to the left of where the real one puts
/// it -- a difference of one byte per character, in every listing.
///
/// ## Why `%8llu` and not "right-aligned at column 42"
///
/// The first guess was "the size's last digit ends at column 42", and it
/// fits every size of one to six digits.  It is wrong for nine: the
/// nine-digit size starts at column 34 and ends at 43, and the WHOLE line
/// grows by one character -- the date moves from column 43 to 44.
///
/// That is exactly what `printf("%8llu", ...)` does when the number does
/// not fit: the field grows instead of truncating.  So the size is
/// printed with a MINIMUM width of eight, and the rest of the line
/// shifts right when the number is wider.  An implementation that
/// right-aligns in a fixed sixteen-column field would put the nine-digit
/// size at [34,43) but keep the date at 43 -- i.e. it would overlap the
/// date, which is not what the server sends.
///
/// ## The date, and the switch between the two forms
///
/// Two forms, both exactly twelve characters:
///
/// ```
/// Nov 11 14:18      recent: "%b %e %H:%M"
/// Oct  7  2025      old:    "%b %e  %Y"
/// ```
///
/// The day is SPACE-padded to two columns (`Oct  7`, not `Oct 7`), and the
/// old form has TWO spaces before the year -- so it is `"%b %e  %Y"`, not
/// `"%b %e %Y"`.
///
/// ## The switch, measured to the second
///
/// `.loop92/probe5.py` bisected it: the form changes when the file's age
/// passes **15768000 seconds**, which is 182.5 days -- half a year.  The
/// bisection ran twice, five seconds apart, and the threshold MOVED with
/// the current time by exactly those five seconds, so the rule compares
/// the file's time against `now` and not against a calendar date.
///
/// And the future is on the OLD side: a file whose mtime is one minute in
/// the future showed `Nov 11  2026`.  So the rule is
///
/// ```
/// recent  <=>  0 <= now - mtime < 15768000
/// ```
///
/// with the threshold itself on the OLD side (age 15767999 is recent,
/// 15768000 is old).
///
/// ## The month names
///
/// English three-letter abbreviations, capital first.  These are what the
/// real server prints, and they are spelled out here rather than left to
/// a calendar library that might print something else.

///|
/// The number of seconds in half a year: the age at which the date form
/// changes.
///
/// 15768000 = 182.5 * 86400.  Measured by bisection to the second
/// (`.loop92/probe5.py`); the second run, five seconds later, put the
/// threshold five seconds later too, which is what makes this a duration
/// rather than a calendar date.
pub const HALF_YEAR_SECONDS : Int64 = 15768000L

///|
/// The three-letter name of a month, 1 to 12.
///
/// A function rather than a constant table, because MoonBit's `const`
/// only takes immutable primitives and an array of strings is not one.
fn month_name(m : Int32) -> String {
  if m == 1 {
    "Jan"
  } else if m == 2 {
    "Feb"
  } else if m == 3 {
    "Mar"
  } else if m == 4 {
    "Apr"
  } else if m == 5 {
    "May"
  } else if m == 6 {
    "Jun"
  } else if m == 7 {
    "Jul"
  } else if m == 8 {
    "Aug"
  } else if m == 9 {
    "Sep"
  } else if m == 10 {
    "Oct"
  } else if m == 11 {
    "Nov"
  } else {
    "Dec"
  }
}

///|
/// The mode string's first four characters: the type and the owner's
/// permission bits.
///
/// Windows has no group and other bits, so those two columns are the
/// literal asterisks the real server sends.  The owner bits are the
/// platform's: a writable file is `rw-`, a read-only one is `r--`, and a
/// directory is `rwx`.
pub fn mode_prefix(is_dir : Bool, is_readonly : Bool) -> String {
  if is_dir {
    "drwx"
  } else if is_readonly {
    "-r--"
  } else {
    "-rw-"
  }
}

///|
/// The whole mode string: ten characters.
pub fn mode_string(is_dir : Bool, is_readonly : Bool) -> String {
  mode_prefix(is_dir, is_readonly) + "******"
}

///|
/// The Unix mode word the server reports in a STAT reply.
///
/// Measured: 33152 for a writable file (`0100600`), 33024 for a
/// read-only one (`0100400`), 16832 for a directory (`040700`).  So the
/// read-only flag removes the OWNER's write bit only, and the group and
/// other bits are zero either way -- because Windows has none.
///
/// ## The "other" field is not a property of the file
///
/// The three numbers above are what the server answers for a file under
/// `C:\Users\<user>\AppData\Local\Temp`, where the directory's access
/// control list grants "everybody" nothing.  Under `E:\` the same file
/// answers 33159 (`0100607`), 33029 (`0100405`) and 16839 (`040707`).
///
/// The difference is exactly the "other" field, and it follows the ACL:
///
/// | the ACL says | the "other" field |
/// |---|---|
/// | `Everyone:(M)` | 7 |
/// | `Everyone:(GR,GE)` | 5 |
/// | `Authenticated Users:(M)` | 7 |
/// | `Authenticated Users:(GR,GE)` | 5 |
/// | `BUILTIN\Users:(M)` | 0 |
/// | `BUILTIN\Users:(RX)` | 0 |
/// | nothing | 0 |
///
/// Measured by `.loop92/probe_acl2.py`, which grants one ACE per
/// directory and reads the number back.  Two things are worth noticing:
/// the rights that count are the GENERIC ones -- an ACE granted the
/// specific `(RX)` moved nothing -- and only the two classes that stand
/// for EVERYBODY count, not the groups the user happens to be in.
///
/// And the write bit is taken away from a read-only file: the ACL grants
/// 7 and the read-only file answers 5.
///
/// So the word is `base + other`, where the base is the file's own
/// attributes and the "other" is the ACL's.
pub fn stat_perm_word(
  is_dir : Bool,
  is_readonly : Bool,
  other_bits : Int32,
) -> Int32 {
  let base = if is_dir { 16832 } else if is_readonly { 33024 } else { 33152 }
  // A read-only file has no write bit, whoever the ACL says.
  let other = if is_readonly { other_bits & 5 } else { other_bits & 7 }
  base + other
}

///|
/// The Unix mode word the server reports in an FSTAT reply.
///
/// Measured on the same files as `stat_perm_word`: 33206 for a writable
/// file and 33060 for a read-only one -- and the same on a directory
/// whose ACL grants "everybody" a lot, so FSTAT does **not** consult it.
///
/// The difference from the STAT word is that the group and other bits are
/// the OWNER's bits rather than nothing, which is what makes the two
/// numbers different for the same file.
pub fn fstat_perm_word(is_readonly : Bool) -> Int32 {
  if is_readonly {
    33060
  } else {
    33206
  }
}

///|
/// The size column: `%8llu`, so right-aligned in eight columns and
/// GROWING when the number is wider.
///
/// Growing rather than truncating is the measured behaviour: the
/// nine-digit size starts at column 34 and ends at 43, pushing the date
/// to column 44.
fn size_column(size : Int64) -> String {
  let digits = decimal(size)
  let pad = 8 - digits.length()
  let sb = StringBuilder()
  let mut i = 0
  while i < pad {
    sb.write_char(' ')
    i = i + 1
  }
  sb.write_string(digits)
  sb.to_string()
}

///|
/// The whole longname.
///
/// `now` is the current time in seconds since the epoch and `offset` is
/// the local offset from UTC in seconds, because the date column is LOCAL
/// time -- the recordings show `14:18` for a file modified at the time
/// the probe ran, and this machine is not at UTC.
pub fn longname(
  name : String,
  is_dir : Bool,
  is_readonly : Bool,
  size : Int64,
  mtime : Int64,
  now : Int64,
  offset : Int64,
) -> String {
  mode_string(is_dir, is_readonly) +
  "    1" +
  " -        -" +
  "        " +
  size_column(size) +
  " " +
  date_column(mtime, now, offset) +
  " " +
  name
}

///|
/// The date column: twelve characters, in one of two forms.
///
/// The form is chosen by the measured rule: recent when the file is in
/// the past and less than half a year old, old otherwise -- which puts a
/// file in the future on the old side.
pub fn date_column(mtime : Int64, now : Int64, offset : Int64) -> String {
  let age = now - mtime
  if age >= 0L && age < HALF_YEAR_SECONDS {
    let (y, mo, d, h, mi, _) = civil_from_epoch(mtime + offset)
    let _ = y
    month_name(mo) + " " + pad2(d) + " " + pad2(h) + ":" + pad2(mi)
  } else {
    let (y, mo, d, _, _, _) = civil_from_epoch(mtime + offset)
    month_name(mo) + " " + pad2(d) + "  " + pad4(y)
  }
}

///|
/// A number in two columns, space-padded on the left.
fn pad2(v : Int32) -> String {
  if v < 10 {
    " " + v.to_string()
  } else {
    v.to_string()
  }
}

///|
/// A year in four columns.
fn pad4(v : Int32) -> String {
  let s = v.to_string()
  if s.length() >= 4 {
    s
  } else if s.length() == 3 {
    "0" + s
  } else if s.length() == 2 {
    "00" + s
  } else {
    "000" + s
  }
}

///|
/// The decimal spelling of a non-negative number.
fn decimal(v : Int64) -> String {
  if v == 0L {
    return "0"
  }
  let digits : Array[String] = []
  let mut n = v
  while n > 0L {
    let d = (n % 10L).to_int()
    digits.push(Int32::unsafe_to_char('0'.to_int() + d).to_string())
    n = n / 10L
  }
  // The digits came out least-significant first, so they go back in
  // reverse.
  let sb = StringBuilder()
  let mut i = digits.length() - 1
  while i >= 0 {
    sb.write_string(digits[i])
    i = i - 1
  }
  sb.to_string()
}

///|
/// Break a Unix time into its civil parts, in LOCAL time.
///
/// The local time is not the epoch: the recordings show `14:18` for a
/// file modified at the time the probe ran, and this machine is at UTC+8,
/// so the conversion has to apply the local offset.  The offset is
/// supplied by the caller rather than computed here, because a rule that
/// reads the machine's timezone is a rule that cannot be tested with a
/// fixed answer -- and the tests here pin exact strings.
///
/// Returns (year, month, day, hour, minute, second).
pub fn civil_from_epoch(
  epoch : Int64,
) -> (Int32, Int32, Int32, Int32, Int32, Int32) {
  let days = floor_div(epoch, 86400L)
  let secs_of_day = epoch - days * 86400L
  let hour = (secs_of_day / 3600L).to_int()
  let minute = (secs_of_day % 3600L / 60L).to_int()
  let second = (secs_of_day % 60L).to_int()
  let (y, m, d) = civil_from_days(days)
  (y, m, d, hour, minute, second)
}

///|
/// The number of whole days, rounding towards minus infinity.
///
/// A negative epoch (a time before 1970) must floor rather than truncate:
/// truncating towards zero would put 1969-12-31 23:00:00 on 1970-01-01.
pub fn floor_div(a : Int64, b : Int64) -> Int64 {
  let q = a / b
  if a % b != 0L && (a < 0L) != (b < 0L) {
    q - 1L
  } else {
    q
  }
}

///|
/// The civil date of a day count since the epoch.
///
/// Howard Hinnant's `civil_from_days`, which is exact over the whole
/// range and has no lookup table to get wrong.
pub fn civil_from_days(z : Int64) -> (Int32, Int32, Int32) {
  let z = z + 719468L
  let era = floor_div(z, 146097L)
  let doe = z - era * 146097L
  let yoe = (doe - doe / 1460L + doe / 36524L - doe / 146096L) / 365L
  let y = yoe + era * 400L
  let doy = doe - (365L * yoe + yoe / 4L - yoe / 100L)
  let mp = (5L * doy + 2L) / 153L
  let d = doy - (153L * mp + 2L) / 5L + 1L
  let m = if mp < 10L { mp + 3L } else { mp - 9L }
  let y = if m <= 2L { y + 1L } else { y }
  (y.to_int(), m.to_int(), d.to_int())
}
