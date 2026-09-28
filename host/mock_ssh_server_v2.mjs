#!/usr/bin/env node
// Mock SSH Server v2 (Loop #22 G2: 完整 USERAUTH/CHANNEL 状态机)
//
// 监听 ws://localhost:2223
// 收 SSH wire frames,模拟 SSH server 完整状态机:
//   VERSION → KEXINIT → KEXECDH_INIT → NEWKEYS → USERAUTH(password) →
//   CHANNEL_OPEN(session) → CHANNEL_REQUEST(exec) → DONE
//
// 字节级解析 client packets (unencrypted path, mock 简化),字节级回包
// server reply 全用 unencrypted (Loop #22 mock 简化 — 加密层留 Loop #25+)
//
// 启动: node host/mock_ssh_server_v2.mjs
//
// 输出格式: 每条 state transition 打印 client packet 摘要 + server reply 字节

import { WebSocketServer } from 'ws';

const PORT = 2223;
const SERVER_VERSION = 'SSH-2.0-MockSSH_1.0\r\n';

// SSH message type bytes
const SH_MSG_KEXINIT = 0x14;
const SH_MSG_NEWKEYS = 0x15;
const SH_MSG_KEX_ECDH_INIT = 0x1e;
const SH_MSG_KEX_ECDH_REPLY = 0x1f;
const SH_MSG_USERAUTH_REQUEST = 0x32;
const SH_MSG_USERAUTH_SUCCESS = 0x34;
const SH_MSG_CHANNEL_OPEN = 0x5a;
const SH_MSG_CHANNEL_OPEN_CONFIRMATION = 0x5b;
const SH_MSG_CHANNEL_DATA = 0x5e;
const SH_MSG_CHANNEL_EOF = 0x5f;
const SH_MSG_CHANNEL_CLOSE = 0x60;
const SH_MSG_CHANNEL_REQUEST = 0x62;
const SH_MSG_CHANNEL_SUCCESS = 0x63;

const wss = new WebSocketServer({ port: PORT });
console.log(`[mock-ssh-v2] listening on ws://localhost:${PORT}`);

wss.on('connection', (ws) => {
  console.log('[mock-ssh-v2] client connected');
  let state = 'VERSION';
  let senderChannel = 0;
  let lastExecCommand = '';

  // 1. 立即发 server version
  ws.send(Buffer.from(SERVER_VERSION));

  ws.on('message', (data) => {
    const bytes = Buffer.from(data);
    console.log(`[mock-ssh-v2] state=${state} recv ${bytes.length}B: ${bytes.toString('hex').substring(0, 80)}`);

    if (state === 'VERSION') {
      // 收 client version
      const ver = bytes.toString('utf-8').trim();
      console.log(`[mock-ssh-v2] client version: ${ver}`);
      ws.send(makeKexInitPacket());
      state = 'KEXINIT';
    } else if (state === 'KEXINIT') {
      // 收 client KEXINIT, parse msg=0x14 + cookie + algs
      const parsed = parseKexInit(bytes);
      console.log(`[mock-ssh-v2] client KEXINIT: cookie=${parsed.cookieHex.substring(0, 16)}..`);
      state = 'KEXECDH_INIT';
    } else if (state === 'KEXECDH_INIT') {
      // 收 client KEXECDH_INIT (msg=0x1e + string Q_C)
      const parsed = parseKexDhInit(bytes);
      console.log(`[mock-ssh-v2] client KEXECDH_INIT: Q_C len=${parsed.qLen}`);
      ws.send(makeKexDhReplyPacket());
      state = 'NEWKEYS';
    } else if (state === 'NEWKEYS') {
      // 收 client NEWKEYS
      const parsed = parseSimplePacket(bytes);
      if (parsed.msgType !== SH_MSG_NEWKEYS) {
        console.error(`[mock-ssh-v2] expected NEWKEYS got ${parsed.msgType}`);
        ws.close();
        return;
      }
      ws.send(makeSimplePacket(SH_MSG_NEWKEYS, Buffer.alloc(0)));
      state = 'USERAUTH';
    } else if (state === 'USERAUTH') {
      // 收 client USERAUTH_REQUEST
      const parsed = parseUserauthRequest(bytes);
      if (parsed.msgType !== SH_MSG_USERAUTH_REQUEST) {
        console.error(`[mock-ssh-v2] expected USERAUTH_REQUEST got ${parsed.msgType}`);
        ws.close();
        return;
      }
      console.log(`[mock-ssh-v2] USERAUTH: user=${parsed.user} method=${parsed.method}` +
                  (parsed.password ? ` password=${parsed.password}` : ''));
      // Loop #22 mock 简化: 直接 SUCCESS (跳过 probe + failure + retry)
      ws.send(makeSimplePacket(SH_MSG_USERAUTH_SUCCESS, Buffer.alloc(0)));
      state = 'CHANNEL_OPEN';
    } else if (state === 'CHANNEL_OPEN') {
      // 收 client CHANNEL_OPEN
      const parsed = parseChannelOpen(bytes);
      if (parsed.msgType !== SH_MSG_CHANNEL_OPEN) {
        console.error(`[mock-ssh-v2] expected CHANNEL_OPEN got ${parsed.msgType}`);
        ws.close();
        return;
      }
      senderChannel = parsed.senderChannel;
      console.log(`[mock-ssh-v2] CHANNEL_OPEN: type=${parsed.type} sender=${parsed.senderChannel}`);
      // 回 CHANNEL_OPEN_CONFIRMATION (recipient=client sender, sender=server 100, window=2M, packet=32K)
      ws.send(makeOpenConfirmation(parsed.senderChannel, 100, 2097152, 32768));
      state = 'CHANNEL_REQUEST';
    } else if (state === 'CHANNEL_REQUEST') {
      // 收 client CHANNEL_REQUEST
      const parsed = parseChannelRequest(bytes);
      if (parsed.msgType !== SH_MSG_CHANNEL_REQUEST) {
        console.error(`[mock-ssh-v2] expected CHANNEL_REQUEST got ${parsed.msgType}`);
        ws.close();
        return;
      }
      console.log(`[mock-ssh-v2] CHANNEL_REQUEST: type=${parsed.type} want_reply=${parsed.wantReply}` +
                  (parsed.command ? ` command="${parsed.command}"` : ''));
      lastExecCommand = parsed.command || '';
      // 回 CHANNEL_SUCCESS
      ws.send(makeSimplePacket(SH_MSG_CHANNEL_SUCCESS, writeU32(senderChannel)));
      // 回 CHANNEL_DATA (mock stdout)
      const mockStdout = `hello from mock server (cmd: ${lastExecCommand})\n`;
      ws.send(makeChannelData(senderChannel, Buffer.from(mockStdout, 'utf-8')));
      // 回 CHANNEL_EOF
      ws.send(makeSimplePacket(SH_MSG_CHANNEL_EOF, writeU32(senderChannel)));
      // 回 CHANNEL_REQUEST "exit-status" (msg=0x62 + recipient_channel + exit_code=0)
      ws.send(makeExitStatus(senderChannel, 0));
      // 回 CHANNEL_CLOSE
      ws.send(makeSimplePacket(SH_MSG_CHANNEL_CLOSE, writeU32(senderChannel)));
      state = 'DONE';
      console.log('[mock-ssh-v2] DONE, waiting for client close');
      setTimeout(() => ws.close(), 1000);
    }
  });

  ws.on('close', () => {
    console.log('[mock-ssh-v2] client disconnected');
  });
});

// ============================================================================
// SSH wire encoding helpers (RFC 4251 + RFC 4253 §6)
// ============================================================================

function makeSimplePacket(msgType, payload) {
  const blockSize = 8;
  const payloadFullLen = 1 + payload.length;
  let padLen = blockSize - (payloadFullLen + 5) % blockSize;
  if (padLen < 4) padLen += blockSize;
  const packetLen = payloadFullLen + padLen + 1;
  const out = Buffer.alloc(4 + 1 + payloadFullLen + padLen);

  out.writeUInt32BE(packetLen, 0);
  out[4] = padLen;
  out[5] = msgType;
  payload.copy(out, 6);
  return out;
}

function writeString(s) {
  const buf = Buffer.alloc(4 + s.length);
  buf.writeUInt32BE(s.length, 0);
  if (typeof s === 'string') {
    Buffer.from(s, 'utf-8').copy(buf, 4);
  } else {
    s.copy(buf, 4);
  }
  return buf;
}

function writeU32(v) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32BE(v, 0);
  return buf;
}

function readString(buf, offset) {
  const len = buf.readUInt32BE(offset);
  const out = buf.subarray(offset + 4, offset + 4 + len);
  return { str: out.toString('utf-8'), len: 4 + len };
}

function readU32(buf, offset) {
  return buf.readUInt32BE(offset);
}

// decode SSH wire packet → { msgType, payload, packetLength, paddingLength }
function parseSimplePacket(bytes) {
  if (bytes.length < 5) return { msgType: -1, payload: Buffer.alloc(0) };
  const packetLength = bytes.readUInt32BE(0);
  const paddingLength = bytes[4];
  const payload = bytes.subarray(5, 5 + packetLength - paddingLength - 1);
  const msgType = payload[0];
  return { msgType, payload: payload.subarray(1), packetLength, paddingLength };
}

function makeKexInitPacket() {
  const cookie = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) cookie[i] = 0xa0 + i;

  const algs = [
    'curve25519-sha256',
    'ssh-ed25519',
    'chacha20-poly1305@openssh.com',
    'chacha20-poly1305@openssh.com',
    'hmac-sha2-256-etm@openssh.com,hmac-sha2-256',
    'hmac-sha2-256-etm@openssh.com,hmac-sha2-256',
    'none', 'none', '', '',
  ];

  const parts = [cookie];
  for (const alg of algs) {
    parts.push(writeString(alg));
  }
  parts.push(Buffer.from([0])); // follows
  parts.push(writeU32(0));      // reserved

  return makeSimplePacket(SH_MSG_KEXINIT, Buffer.concat(parts));
}

function makeKexDhReplyPacket() {
  const alg = writeString('ssh-ed25519');
  const pubkey = Buffer.alloc(32, 0x42);
  const ksBlob = Buffer.concat([alg, pubkey]);
  const ksStr = writeString(ksBlob);
  const qs = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) qs[i] = (i * 7) & 0xff;
  const qsStr = writeString(qs);
  const sig = Buffer.alloc(64);
  const sigStr = writeString(sig);
  return makeSimplePacket(SH_MSG_KEX_ECDH_REPLY, Buffer.concat([ksStr, qsStr, sigStr]));
}

function makeOpenConfirmation(recipient, sender, window, max) {
  const p = Buffer.alloc(16);
  p.writeUInt32BE(recipient, 0);
  p.writeUInt32BE(sender, 4);
  p.writeUInt32BE(window, 8);
  p.writeUInt32BE(max, 12);
  return makeSimplePacket(SH_MSG_CHANNEL_OPEN_CONFIRMATION, p);
}

function makeChannelData(channel, data) {
  const p = Buffer.concat([writeU32(channel), writeString(data)]);
  return makeSimplePacket(SH_MSG_CHANNEL_DATA, p);
}

function makeExitStatus(channel, code) {
  const p = Buffer.concat([writeU32(channel), writeU32(code)]);
  return makeSimplePacket(SH_MSG_CHANNEL_REQUEST, p);
}

// ============================================================================
// Client packet byte-level parsers
// ============================================================================

function parseKexInit(bytes) {
  const p = parseSimplePacket(bytes);
  const cookie = p.payload.subarray(0, 16);
  return { msgType: p.msgType, cookieHex: cookie.toString('hex') };
}

function parseKexDhInit(bytes) {
  const p = parseSimplePacket(bytes);
  // payload: string Q_C (u32 length + 32 bytes)
  const qLen = readU32(p.payload, 0);
  return { msgType: p.msgType, qLen };
}

function parseUserauthRequest(bytes) {
  const p = parseSimplePacket(bytes);
  let off = 0;
  const user = readString(p.payload, off); off += user.len;
  const service = readString(p.payload, off); off += service.len;
  const method = readString(p.payload, off); off += method.len;
  let password = null;
  if (method.str === 'password') {
    const boolByte = p.payload[off]; off += 1;
    const pw = readString(p.payload, off); off += pw.len;
    if (boolByte === 1) password = pw.str;
  }
  return { msgType: p.msgType, user: user.str, service: service.str, method: method.str, password };
}

function parseChannelOpen(bytes) {
  const p = parseSimplePacket(bytes);
  let off = 0;
  const type = readString(p.payload, off); off += type.len;
  const senderChannel = readU32(p.payload, off); off += 4;
  const windowSize = readU32(p.payload, off); off += 4;
  const packetSize = readU32(p.payload, off); off += 4;
  return { msgType: p.msgType, type: type.str, senderChannel, windowSize, packetSize };
}

function parseChannelRequest(bytes) {
  const p = parseSimplePacket(bytes);
  let off = 0;
  const channel = readU32(p.payload, off); off += 4;
  const type = readString(p.payload, off); off += type.len;
  const wantReply = p.payload[off]; off += 1;
  let command = null;
  if (type.str === 'exec') {
    const cmd = readString(p.payload, off); off += cmd.len;
    command = cmd.str;
  }
  return { msgType: p.msgType, type: type.str, wantReply: wantReply === 1, command };
}

// Trap uncaught
process.on('uncaughtException', (e) => {
  console.error('uncaught:', e);
  process.exit(1);
});