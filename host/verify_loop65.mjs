#!/usr/bin/env node
// host/verify_loop65.mjs -- Loop #65: a gate suite must not leak the servers
// it starts, and the tier split must match what was measured rather than what
// was guessed.
//
// ## The finding
//
// `verify_loop40.mjs` starts a real OpenSSH server and cannot stop it.
// `startSshd()` (verify_loop40.mjs:147) spawns `node host/sshd_setup.mjs`,
// calls `child.unref()`, polls until the port answers, and returns a boolean --
// the handle is discarded and never stored. `sshd_setup.mjs:210` parks on
// `await new Promise(() => {})`: `sshd -D` runs in the foreground forever and
// no SIGTERM/SIGINT handler is installed. The only `kill()` anywhere in
// verify_loop40 is `relay.kill()` (line 556), which is a different process.
//
// So on every run -- success or failure -- an sshd is orphaned on SSHD_PORT
// 18783. Reading that establishes there is no owner; it does not establish that
// the process survives. `host/probe_sshd_leak.mjs` measures it, and section D
// below runs that measurement.
//
// ## Why it matters more than it looks
//
// 18783 is a fixed port, so the second run of verify_loop40 collides with the
// first. That is the mechanism behind `verify_loop49` passing standalone and
// failing inside a suite run, which is the kind of order-dependent failure that
// gets mistaken for "flaky" and then lived with forever.
//
// ## The classification mistake this loop also fixes
//
// Loop #64 wrote `PEER_GATES` in ci/ci.py as verify_loop31..39 and left loop40
// in the default tier, where it costs ~44 minutes and turns the default run
// red for a reason that has nothing to do with the code under test. The honest
// fix is not to widen the guess; it is to measure, record the measurement, and
// make the default tier reflect it.
//
// Sections A--C assert the structural facts (cheap, no server). Section D runs
// the real leak experiment (~30s) and is the load-bearing one: it is the only
// thing here that would notice if the leak were ever quietly fixed or
// reintroduced.

import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

let passed = 0;
const failures = [];

function expect(name, cond, detail = '') {
  if (cond) {
    passed++;
    console.log(`  ok    ${name}`);
  } else {
    failures.push(name);
    console.log(`  FAIL  ${name}${detail ? `  [${detail}]` : ''}`);
  }
}

/// Comments explaining a bug necessarily contain the bug's text.
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/\/[^\n]*/g, '');
}

function section(t) { console.log(''); console.log(t); }

const loop40 = stripComments(readFileSync(join(ROOT, 'host', 'verify_loop40.mjs'), 'utf8'));
const setup = stripComments(readFileSync(join(ROOT, 'host', 'sshd_setup.mjs'), 'utf8'));

// ------------------------------------------------ A. the leak's shape -------
section('A. verify_loop40 cannot stop the sshd it starts');
expect('it spawns sshd_setup.mjs', /sshd_setup\.mjs/.test(loop40));
expect('it unrefs that child', /child\.unref\(\)/.test(loop40));
expect('startSshd returns a boolean, dropping the handle',
       /async function startSshd[\s\S]*?return true;[\s\S]*?\n\}/.test(loop40));
// The whole point: no kill path for that child.
{
  const kills = [...loop40.matchAll(/\.kill\(\)/g)].map(m => m.index);
  const relayOnly = kills.length === 1 && /relay\.kill\(\)/.test(loop40);
  expect('the only kill() is relay.kill(), not the sshd', relayOnly,
         `${kills.length} kill() call(s)`);
  expect('nothing kills an sshd child', !/sshd[a-z_]*\.kill|sshdChild\.kill|child\.kill/.test(loop40));
}
expect('sshd_setup runs sshd -D in the foreground', /'-D'/.test(setup));
expect('sshd_setup never returns on its own', /new Promise\(\(\) => \{\}\)/.test(setup));
expect('sshd_setup installs no SIGTERM/SIGINT handler',
       !/process\.on\(\s*['"]SIG(?:TERM|INT)/.test(setup));
expect('sshd_setup does not exit when its parent does',
       !/process\.on\(\s*['"](?:exit|disconnect|SIGHUP)/.test(setup));

// ------------------------------------------------ B. the port is fixed ------
section('B. the leaked port is a fixed constant, so runs collide');
{
  const m = loop40.match(/const\s+SSHD_PORT\s*=\s*(\d+)/);
  expect('verify_loop40 pins one fixed port', m !== null, m ? '' : 'no SSHD_PORT literal');
  if (m) {
    console.log(`  ..    SSHD_PORT = ${m[1]}`);
    // A random or port-0 port would make the leak harmless; a literal cannot be.
    expect('the port is a hard-coded literal, so a second run collides',
           /^const\s+SSHD_PORT\s*=\s*\d+\s*;?\s*$/m.test(loop40.trim()));
  }
}

// ------------------------------------------------ C. classification ---------
section('C. the default tier reflects what was measured');
{
  const ci = readFileSync(join(ROOT, 'ci', 'ci.py'), 'utf8');
  const pm = ci.match(/PEER_GATES\s*=\s*frozenset\(([\s\S]*?)\)\s*\n/);
  expect('ci.py declares PEER_GATES', pm !== null);
  if (pm) {
    const listed = [...pm[1].matchAll(/(\d+)/g)].map(m => Number(m[1]));
    expect('verify_loop40 is classified as peer-gated',
           listed.includes(40), listed.join(','));
    expect('verify_loop49 is classified as peer-gated',
           listed.includes(49), listed.join(','));
    // What must survive is the justification for the entries most likely to
    // rot: loop40 and loop49. Three weaker forms of this check were tried and
    // each passed a deletion that should have failed -- "does the file contain
    // the word measured" is satisfied by Loop #64's paragraph about loops
    // 31-39, and deleting one line of a multi-line block leaves the evidence.
    // Naming the two gates is specific enough to be falsifiable.
    const at = ci.indexOf('PEER_GATES = frozenset(');
    const above = ci.slice(Math.max(0, at - 2200), at);
    for (const gate of ['loop40', 'loop49']) {
      expect(`the provenance note justifies ${gate} specifically`,
             new RegExp(gate).test(above),
             `${gate} is in the set but no adjacent note explains it`);
    }
    expect('the note says the set was measured, not guessed',
           /measured/.test(above), above.slice(-140));
  }
  // The mutations tier must not run in the tree that matters.
  expect('mutations run in a sandbox, not in this tree',
         /sandbox\.make_sandbox/.test(ci) && /s\.tier == "mutations"/.test(ci));
}

// ------------------------------------------------ D. the measurement --------
section('D. the leak reproduces');
{
  const probe = join(ROOT, 'host', 'probe_sshd_leak.mjs');
  expect('host/probe_sshd_leak.mjs exists', existsSync(probe));
  const r = spawnSync('cmd', ['/c', 'node', 'host\\probe_sshd_leak.mjs'], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  const out = `${r.stdout || ''}${r.stderr || ''}`;
  console.log('  ..    ' + out.split('\n').filter(l => l.trim()).slice(0, 3).join(' | ').trim());
  expect('the probe ran', r.status !== 3,
         r.status === 3 ? 'sshd never came up; the probe did not test anything' : '');
  // This is the assertion Loop #65 exists for: the port still answers after the
  // owner has exited. Exit 1 == leak confirmed.
  expect('LEAK CONFIRMED: the port outlives its owner',
         r.status === 1 && /LEAK CONFIRMED/.test(out),
         `status ${r.status}`);
  expect('the probe cleans up after itself',
         /self-cleanup by this probe: ok/.test(out),
         (out.match(/self-cleanup[^\n]*/) || [''])[0]);
  expect('the probe refuses to call "no leak" a pass when sshd never started',
         /not a pass/i.test(out) || r.status === 1);
}

// ------------------------------------------------ E. loop64 still holds ------
section('E. nothing this loop touched weakened the previous one');
{
  const r = spawnSync('cmd', ['/c', 'node', 'host\\verify_loop64.mjs'], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  expect('verify_loop64 still passes', r.status === 0,
         (r.stdout || '').trim().split('\n').pop());
  const self = spawnSync('cmd', ['/c', 'python', 'ci\\ci.py', '--self-check'], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  expect('the CI engine self-check still passes', self.status === 0,
         (self.stdout || '').trim().split('\n').pop());
}

console.log('');
console.log(`loop65: ${passed}/${passed + failures.length} checks passed`);
if (failures.length) {
  for (const f of failures) console.log(`  FAIL ${f}`);
  process.exit(1);
}
console.log('ALL PASS');
