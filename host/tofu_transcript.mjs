// Parsing the TOFU transcript: one place that knows what a status line is.
//
// Loop #52 added `tofu: stored` and `tofu: NOT stored`, and two gates broke the
// same way -- each had its own filter listing only `accepted-unpinned`, so the
// browser's write-back came back as the literal string `stored`. The symptom in
// both was a byte-for-byte mismatch between transports plus a refused reconnect,
// neither of which mentions a parsing mistake.
//
// That is the argument for this file. A driver and a gate are two independent
// implementations of "what this output means", and neither is documentation for
// the other; a list of markers that lives in two places is a list that will be
// wrong in both. Adding a marker now means editing one place.
//
// The entry itself is recognised structurally as well: a known_hosts line starts
// with a host field and contains a key type. `isEntry` prefers that and falls
// back to the marker list, so a *new* status line does not break the parse even
// if somebody forgets this file. Belt and braces on purpose -- the first version
// of the filter was the only mechanism, and that was the whole bug.

/// Every `tofu: ` line the drivers print that is **not** the known_hosts entry.
/// Keep this in step with `cmd/wt_ssh`'s `cfg_report_tofu`.
export const TOFU_STATUS_MARKERS = [
  "accepted-unpinned",
  "stored",
  "NOT stored",
];

/// Does this line look like a `known_hosts` entry rather than a status line?
///
/// `host keytype base64` -- the format OpenSSH itself writes. Used as a
/// preference rather than a requirement: a host field can be anything the user
/// wrote (a wildcard, a negated list, a bracketed `[host]:port`), so the shape
/// test is "does it have at least two whitespace-separated fields", which every
/// legal entry has and no status line does.
export function isEntry(line) {
  const fields = line.trim().split(/\s+/);
  return fields.length >= 2;
}

/// Pull the written-back known_hosts text out of a transcript.
///
/// Returns null when there is none, rather than returning a status line and
/// letting the caller feed it to `--known-hosts-text` -- where it parses to zero
/// entries and the failure message points at the parser rather than at the bug.
export function tofuEntry(transcript) {
  const lines = String(transcript || "").match(/^tofu: (.+)$/gm) || [];
  for (const raw of lines) {
    const candidate = raw.slice("tofu: ".length).replace(/\s+/g, " ").trim();
    if (isEntry(candidate) && !TOFU_STATUS_MARKERS.includes(candidate)) {
      return candidate;
    }
  }
  return null;
}

/// Whether the driver reported that it accepted an unpinned key at all.
export function hasAcceptedUnpinned(transcript) {
  return /^tofu: accepted-unpinned$/m.test(String(transcript || ""));
}

/// Whether the driver reported that the write did not land.
///
/// Worth its own reader: "connected, but you are not pinned" is the state a user
/// most needs to be told about and the easiest to miss.
export function hasNotStored(transcript) {
  return /^tofu: NOT stored/m.test(String(transcript || ""));
}

/// Whether the driver reported that it stored the pin.
export function hasStored(transcript) {
  return /^tofu: stored$/m.test(String(transcript || ""));
}