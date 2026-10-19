// host/keep_output.mjs -- keep the whole child output, print the tail of it.
//
// ## The defect this exists to end
//
// Loop #69 found that `ci/ci.py` kept only the last 12 lines of a failing step,
// which made a 928-second failure arrive as a fragment and cost a full 25-minute
// CI run to diagnose. That fix was applied to the engine.
//
// Then run 39200128854 arrived and showed the same disease one level down, in
// three places at once:
//
//   verify_loop41          `FAIL moon build  Error: failed to run build for
//                          target Native` -- and then not one line of the
//                          compiler's actual complaint
//   verify_loop55          `BUILD FAILED | The system cannot find the path
//                          specified.` -- the one line that WAS kept is the
//                          wrapper's echo, not cl's or gcc's error
//   host/probe_sshd_leak   `sshd never came up; the probe did not test
//                          anything` -- sshd's own stderr, which says why,
//                          was discarded
//
// So: **the evidence chain has a hole at every layer that summarises a child
// process.** The engine was the only one fixed. This module makes the fix a
// one-call change at the next layer down, and makes it greppable.
//
// ## Why not just print everything
//
// Because then the console is unreadable, which is how these summaries started.
// The split is deliberate:
//
//   - the summary stays, so the terminal and the 12-line tail are still
//     something a human can scan;
//   - the full transcript goes to `.loop70/<label>.log`, gitignored and
//     overwritten every run, so it is there the moment the run ends.
//
// This is the same shape as Loop #42 defect 3's fix, and Loop #69's. Three
// loops, three layers, one habit: **the failure and its evidence land together,
// or the evidence is gone.**
//
// ## Using it
//
//   import { keep } from './keep_output.mjs';
//   ok  = r.status === 0;
//   bad('moon build', ok ? '' : keep('moon-build', r.text));
//
// `keep` returns the tail for the inline message; it does not change what the
// caller prints. A caller that wants a different tail length passes one.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIR = join(ROOT, '.loop70');

const DEFAULT_TAIL = 300;

// Label -> path, so two failures with the same label in one run do not
// overwrite each other's evidence silently. The suffix is the call order,
// which is stable within a run and meaningless outside it -- the point is
// only that no earlier transcript is lost.
const written = new Map();
let counter = 0;

/** Keep `text` under `.loop70/` and return its last `tail` characters. */
export function keep(label, text, tail = DEFAULT_TAIL) {
  const body = String(text ?? '');
  counter += 1;
  const safe = String(label).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 80);
  const name = `${String(counter).padStart(2, '0')}_${safe}.log`;
  written.set(name, body);
  try {
    mkdirSync(DIR, { recursive: true });
    writeFileSync(join(DIR, name), body, 'utf8');
  } catch {
    // Losing the transcript must not turn a red gate into a crashing one. The
    // caller is about to report the failure anyway; that report is the
    // contract, this file is the convenience.
  }
  if (body.length <= tail) return body;
  return '...' + body.slice(-tail);
}

/** What has been kept this run. Used by the Loop #70 gate. */
export function kept() {
  return [...written.entries()].map(([name, body]) => ({
    name,
    bytes: Buffer.byteLength(body, 'utf8'),
  }));
}

/**
 * Whether a label's transcript is on disk AND is longer than the tail the
 * caller printed. This is the assertion that matters: a helper that writes the
 * same 300 characters it already showed has added nothing.
 */
export function keptMoreThan(label) {
  for (const [name, body] of written) {
    if (name.endsWith(`_${String(label).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 80)}.log`)) {
      return Buffer.byteLength(body, 'utf8');
    }
  }
  return 0;
}
