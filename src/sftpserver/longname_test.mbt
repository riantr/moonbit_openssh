///| Loop #92: the `ls -l` line the server builds.
///
/// Every expectation here is a line the REAL `sftp-server.exe` sent --
/// recorded in `.loop92/probe2_out.txt` and `.loop92/probe7_out.txt` -- and
/// every one of them was first replayed through the rule in
/// `.loop92/longname_rule.py`, which reproduced all 23 recorded lines
/// exactly.  So what is pinned here is the RULE, not one lucky example.
///
/// The clock is pinned as well.  A rule that read the machine's own clock
/// could only be checked against a clock, which is a way of not checking
/// it; with the moment and the offset fixed, the date column is a
/// constant string and a change in it is a change in the rule.

///|
/// The moment the probe2 recording was made: 2026-11-11 14:18 local.
const P2_NOW : Int64 = 1794377892L

///|
/// The moment the probe7 recording was made: 2026-11-11 14:41 local.
const P7_NOW : Int64 = 1794379260L

///|
/// This machine's offset from UTC while the recordings were made.
const OFFSET : Int64 = 28800L

///|
/// A day, in seconds.
const DAY : Int64 = 86400L

///|
/// The ten lines probe2 recorded, one per interesting name and size.
///
/// The sizes are the point: `123456789` is nine digits and the line grows
/// by one character, because the server prints the size with `%8llu` and a
/// number that does not fit makes the FIELD grow rather than the line
/// being truncated.  A layout that right-aligned the size in a fixed
/// sixteen-column field would put the nine-digit size and the date in the
/// same place.
test "the_longname_lines_the_real_server_sent" {
  let age = P2_NOW
  assert_eq(
    @sftpserver.longname("a", false, false, 0L, age, P2_NOW, OFFSET),
    "-rw-******    1 -        -               0 Nov 11 14:18 a",
  )
  assert_eq(
    @sftpserver.longname(
      "a-20-characters-name",
      false,
      false,
      1234L,
      age,
      P2_NOW,
      OFFSET,
    ),
    "-rw-******    1 -        -            1234 Nov 11 14:18 a-20-characters-name",
  )
  assert_eq(
    @sftpserver.longname(
      "a-name-of-thirty-six-characters-here",
      false,
      false,
      123456789L,
      age,
      P2_NOW,
      OFFSET,
    ),
    "-rw-******    1 -        -        123456789 Nov 11 14:18 a-name-of-thirty-six-characters-here",
  )
  assert_eq(
    @sftpserver.longname(
      "a-very-long-name-of-fifty-five-characters-in-total-x",
      false,
      false,
      1L,
      age,
      P2_NOW,
      OFFSET,
    ),
    "-rw-******    1 -        -               1 Nov 11 14:18 a-very-long-name-of-fifty-five-characters-in-total-x",
  )
  assert_eq(
    @sftpserver.longname("abcdefgh", false, false, 5L, age, P2_NOW, OFFSET),
    "-rw-******    1 -        -               5 Nov 11 14:18 abcdefgh",
  )
  assert_eq(
    @sftpserver.longname("big.bin", false, false, 307200L, age, P2_NOW, OFFSET),
    "-rw-******    1 -        -          307200 Nov 11 14:18 big.bin",
  )
  // The directory's line: `drwx` and the old date form.
  assert_eq(
    @sftpserver.longname(
      "d-old400",
      true,
      false,
      0L,
      P2_NOW - 400L * DAY,
      P2_NOW,
      OFFSET,
    ),
    "drwx******    1 -        -               0 Oct  7  2025 d-old400",
  )
  assert_eq(
    @sftpserver.longname(
      "old200",
      false,
      false,
      7L,
      P2_NOW - 200L * DAY,
      P2_NOW,
      OFFSET,
    ),
    "-rw-******    1 -        -               7 Apr 25  2026 old200",
  )
  assert_eq(
    @sftpserver.longname(
      "old400",
      false,
      false,
      7L,
      P2_NOW - 400L * DAY,
      P2_NOW,
      OFFSET,
    ),
    "-rw-******    1 -        -               7 Oct  7  2025 old400",
  )
  assert_eq(
    @sftpserver.longname(
      "recent30",
      false,
      false,
      7L,
      P2_NOW - 30L * DAY,
      P2_NOW,
      OFFSET,
    ),
    "-rw-******    1 -        -               7 Oct 12 14:18 recent30",
  )
}

///|
/// A read-only file's mode is `-r--`, and the six asterisks are literal.
///
/// Measured on `ro.txt` in `.loop92/probe7_out.txt`.
test "a_read_only_file_starts_with_dash_r_dash_dash" {
  assert_eq(
    @sftpserver.longname("ro.txt", false, true, 2L, P7_NOW, P7_NOW, OFFSET),
    "-r--******    1 -        -               2 Nov 11 14:41 ro.txt",
  )
}

///|
/// The size column is `%8llu`: eight columns, and it GROWS.
///
/// The nine-digit case is the one that separates "right-aligned in eight"
/// from "right-aligned in a fixed field", and it is why the rule is
/// written as a minimum width rather than a padding count.
test "the_size_column_has_a_minimum_width_of_eight" {
  let now = P2_NOW
  // One digit: seven spaces and the digit.
  let small = @sftpserver.longname("f", false, false, 1L, now, P2_NOW, OFFSET)
  // The size's last digit ends at column 41.
  assert_eq(small[41], '1')
  assert_eq(small[33], ' ')
  // Nine digits: the field grows, so the date moves one column right.
  let big = @sftpserver.longname(
    "f",
    false,
    false,
    123456789L,
    now,
    P2_NOW,
    OFFSET,
  )
  assert_eq(big[34], '1')
  assert_eq(big[42], '9')
  // The date now starts at column 44 instead of 43.
  assert_eq(big[44], 'N')
  assert_eq(small[43], 'N')
}

///|
/// The date changes form at an age of 15768000 seconds -- half a year.
///
/// Measured by bisection, twice, five seconds apart: the threshold MOVED
/// with the current time by exactly those five seconds, so the rule
/// compares against `now` and not against a calendar date.
test "the_date_changes_form_at_half_a_year" {
  let half = @sftpserver.HALF_YEAR_SECONDS
  let now = P2_NOW
  let just_recent = @sftpserver.longname(
    "f",
    false,
    false,
    0L,
    now - half + 1L,
    now,
    OFFSET,
  )
  let just_old = @sftpserver.longname(
    "f",
    false,
    false,
    0L,
    now - half,
    now,
    OFFSET,
  )
  // Recent: the clock.  Old: the year.
  //
  // The recent form is `MMM DD HH:MM` and the old one is `MMM DD  YYYY`,
  // so the two are told apart by the colon and by the four digits.
  assert_true(just_recent.contains(":"))
  assert_false(just_recent.contains("2026"))
  assert_true(just_old.contains("2026"))
  assert_false(just_old.contains(":"))
}

///|
/// A file whose time is in the FUTURE uses the old form.
///
/// Measured: a file one minute in the future showed the year, not the
/// clock.  So the rule is `0 <= now - mtime < 15768000`, and the future is
/// on the OLD side of it.
test "a_future_time_uses_the_year" {
  let now = P2_NOW
  let future = @sftpserver.longname(
    "f",
    false,
    false,
    0L,
    now + 60L,
    now,
    OFFSET,
  )
  assert_true(future.contains("2026"))
  assert_false(future.contains("14:18"))
}

///|
/// The two permission words, which are NOT the same.
///
/// Measured on the same file in the same session: `STAT` says 33152
/// (`0100600`) and `FSTAT` says 33206 (`0100666`).  The difference is
/// exactly the group and other bits, which `STAT` leaves at zero and
/// `FSTAT` fills in.  A server that used one word for both would answer
/// `FSTAT` with a number the real server never sends.
test "the_two_permission_words_are_different" {
  assert_eq(@sftpserver.stat_perm_word(false, false, 0), 33152)
  assert_eq(@sftpserver.stat_perm_word(false, true, 0), 33024)
  assert_eq(@sftpserver.stat_perm_word(true, false, 0), 16832)
  assert_eq(@sftpserver.fstat_perm_word(false), 33206)
  assert_eq(@sftpserver.fstat_perm_word(true), 33060)
}

///|
/// The mode string: the type and the owner's three bits.
///
/// The group and other columns are LITERAL asterisks, because Windows has
/// no group and no other.
test "the_mode_string_has_ten_characters" {
  assert_eq(@sftpserver.mode_string(false, false), "-rw-******")
  assert_eq(@sftpserver.mode_string(false, true), "-r--******")
  assert_eq(@sftpserver.mode_string(true, false), "drwx******")
}

///|
/// The permission word carries the ACL's "other" bits, and FSTAT does
/// not.
///
/// Measured: the same file answers 0o100600 under a directory whose ACL
/// grants nobody anything and 0o100607 under one whose ACL grants
/// "everybody" full control.  The read-only file takes the write bit off
/// the ACL's answer: 0o100607 becomes 0o100405.  And `FSTAT` answers
/// 0o100666 in both directories, so it does not look at the ACL at all.
test "the_permission_word_carries_the_acl_bits" {
  assert_eq(@sftpserver.stat_perm_word(false, false, 0), 33152)
  assert_eq(@sftpserver.stat_perm_word(false, false, 7), 33159)
  assert_eq(@sftpserver.stat_perm_word(false, true, 0), 33024)
  // The ACL grants 7, but a read-only file has no write bit.
  assert_eq(@sftpserver.stat_perm_word(false, true, 7), 33029)
  assert_eq(@sftpserver.stat_perm_word(true, false, 0), 16832)
  assert_eq(@sftpserver.stat_perm_word(true, false, 7), 16839)
  // FSTAT repeats the owner's bits into the group and other columns.
  assert_eq(@sftpserver.fstat_perm_word(false), 33206)
  assert_eq(@sftpserver.fstat_perm_word(true), 33060)
}

///|
/// The civil date, from a day count.
///
/// Howard Hinnant's algorithm, checked at the three points that catch a
/// wrong century rule: the epoch itself, a leap day, and the year before
/// a leap year.
test "the_civil_date_is_the_measured_one" {
  let e = @sftpserver.civil_from_days(0)
  assert_eq(e.0, 1970)
  assert_eq(e.1, 1)
  assert_eq(e.2, 1)
  // 2024-02-29 is day 19782.
  let leap = @sftpserver.civil_from_days(19782)
  assert_eq(leap.0, 2024)
  assert_eq(leap.1, 2)
  assert_eq(leap.2, 29)
  // 2023-12-31 is day 19722.
  let before = @sftpserver.civil_from_days(19722)
  assert_eq(before.0, 2023)
  assert_eq(before.1, 12)
  assert_eq(before.2, 31)
}

///|
/// The day count of the recording, so the two tests above are about the
/// same date the server sent.
test "the_day_count_of_the_recording" {
  // 2026-11-11 is 20768 days after 1970-01-01.
  let e = @sftpserver.civil_from_days(20768)
  assert_eq(e.0, 2026)
  assert_eq(e.1, 11)
  assert_eq(e.2, 11)
}
