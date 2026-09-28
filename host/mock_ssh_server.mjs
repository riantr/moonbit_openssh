#!/usr/bin/env node
// Mock SSH Server (Loop #20 端到端 demo)
// 监听 ws://localhost:2222
// 收 SSH wire frames,模拟 SSH server 状态机
// hardcode client K → 推 shared secret → server reply 加密
//
// 简化: server 不发 reply (client-only 验证字节路径)
//        server 发 unencrypted 版本字符串 + KEXINIT 后 chatty 调试
//
// 启动: node host/mock_ssh_server.mjs

import { WebSocketServer } from 'ws';
import { createHash } from 'node:crypto';

const PORT = 2222;
const SERVER_VERSION = 'SSH-2.0-MockSSH_1.0\r\n';

const SSH_MSG_KEXINIT = 0x14;
const SSH_MSG_NEWKEYS = 0x15;
const SSH_MSG_KEX_ECDH_REPLY = 0x1f;
const SSH_MSG_USERAUTH_SUCCESS = 0x34;
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 0x5b;
const SSH_MSG_CHANNEL_SUCCESS = 0x63;
const SSH_MSG_CHANNEL_DATA = 0x5e;
const SSH_MSG_CHANNEL_EOF = 0x5f;
const SSH_MSG_CHANNEL_CLOSE = 0x60;

const wss = new WebSocketServer({ port: PORT });
console.log(`[mock-ssh] listening on ws://localhost:${PORT}`);

wss.on('connection', (ws) => {
  console.log('[mock-ssh] client connected');
  let state = 'VERSION';
  let receiveBytes = Buffer.alloc(0);

  // 1. 立即发 server version
  ws.send(Buffer.from(SERVER_VERSION));

  ws.on('message', (data) => {
    const bytes = Buffer.from(data);
    console.log(`[mock-ssh] state=${state} recv ${bytes.length}B: ${bytes.toString('hex').substring(0, 60)}`);

    if (state === 'VERSION') {
      // 收 client version
      const ver = bytes.toString('utf-8').trim();
      console.log(`[mock-ssh] client version: ${ver}`);
      // 发 server KEXINIT
      ws.send(makeKexInitPacket());
      state = 'KEXINIT_RECV';
    } else if (state === 'KEXINIT_RECV') {
      // 收 client KEXINIT,等 client KEXECDH_INIT
      console.log(`[mock-ssh] got client KEXINIT (${bytes.length}B), waiting KEXECDH_INIT`);
      state = 'KEXECDH_INIT';
    } else if (state === 'KEXECDH_INIT') {
      // 收 client KEXECDH_INIT,发 server KEXDH_REPLY
      console.log(`[mock-ssh] got client KEXECDH_INIT (${bytes.length}B), sending KEXDH_REPLY`);
      ws.send(makeKexDhReplyPacket(bytes));
      state = 'NEWKEYS';
    } else if (state === 'NEWKEYS') {
      // 收 client NEWKEYS (unencrypted),发 server NEWKEYS
      console.log(`[mock-ssh] got client NEWKEYS, sending server NEWKEYS`);
      ws.send(makeSimplePacket(SSH_MSG_NEWKEYS, Buffer.alloc(0)));
      // Loop #20: 不发 reply (简化),client-only 验证
      // 真实 SSH: server 也要切 Aead mode 后发 USERAUTH_SUCCESS 等
      console.log(`[mock-ssh] demo completed, closing`);
      setTimeout(() => ws.close(), 100);
      state = 'DONE';
    }
  });

  ws.on('close', () => {
    console.log('[mock-ssh] client disconnected');
  });
});

///| 构造 server KEXINIT packet (deterministic)
function makeKexInitPacket() {
  const payload = Buffer.alloc(256);
  let off = 0;
  // cookie (16 bytes random)
  for (let i = 0; i < 16; i++) payload[off + i] = i + 0xa0;
  off += 16;
  // 10 proposal strings
  const algs = [
    'curve25519-sha256',               // kex
    'ssh-ed25519',                     // hostkey
    'chacha20-poly1305@openssh.com',   // enc c→s
    'chacha20-poly1305@openssh.com',   // enc s→c
    'hmac-sha2-256-etm@openssh.com,hmac-sha2-256',  // mac c→s
    'hmac-sha2-256-etm@openssh.com,hmac-sha2-256',  // mac s→c
    'none',                            // comp c→s
    'none',                            // comp s→c
    '',                                // lang c→s
    '',                                // lang s→c
  ];
  for (const alg of algs) {
    const buf = Buffer.from(alg, 'utf-8');
    payload.writeUInt32BE(buf.length, off); off += 4;
    buf.copy(payload, off); off += buf.length;
  }
  // follows (1 byte) + reserved (4 bytes)
  payload[off++] = 0;
  payload.writeUInt32BE(0, off); off += 4;
  // padding to 8-byte block: payload.length = 256 (0 mod 8 = 0),但 packet_length 至少 1+4+16+...
  // packet = 4(len) + 1(padlen) + 1 + payload + padding
  // 简化 - 重新算
  return makeSimplePacket(SSH_MSG_KEXINIT, payload.subarray(0, off));
}

///| 构造 server KEXDH_REPLY (deterministic, unencrypted for Loop #20 demo)
function makeKexDhReplyPacket(clientKexDhInit) {
  // Server K_S (hostkey) - hardcode deterministic ed25519 public key
  // For demo: simplified - just send a fixed blob
  const hostkeyBlob = Buffer.from([
    // ssh-ed25519 blob: u32 len("ssh-ed25519") + "ssh-ed25519" + ed25519 pubkey (32 bytes)
    0, 0, 0, 11, ...Buffer.from('ssh-ed25519'), ...new Uint8Array(32).fill(0x42)
  ]);
  // Server Q_S (x25519 public) - hardcode
  const serverPub = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) serverPub[i] = (i * 7) & 0xff;
  // Signature (simplified - just zeros)
  const sig = Buffer.alloc(64);

  // payload: K_S || Q_S || sig
  const payload = Buffer.concat([hostkeyBlob, writeString(serverPub), writeString(sig)]);
  // First byte of payload is msg_type (need to prepend 0x1f)
  return makeSimplePacket(SSH_MSG_KEX_ECDH_REPLY, payload);
}

///| 构造 SSH packet (RFC 4253 §6)
function makeSimplePacket(msgType, payload) {
  const blockSize = 8;
  const payloadFullLen = 1 + payload.length;
  let padLen = blockSize - (payloadFullLen + 5) % blockSize;
  if (padLen < 4) padLen += blockSize;
  const packetLen = payloadFullLen + padLen + 1;
  const total = 4 + packetLen + 1; // 4 len + 1 msgType + payload + padLen + pad
  const out = Buffer.alloc(4 + 1 + payloadFullLen + padLen);

  out.writeUInt32BE(packetLen, 0);
  out[4] = padLen;
  out[5] = msgType;
  payload.copy(out, 6);
  // padding bytes zero
  return out;
}

function writeString(s) {
  const buf = Buffer.alloc(4 + s.length);
  buf.writeUInt32BE(s.length, 0);
  Buffer.from(s).copy(buf, 4);
  return buf;
}

// Trap uncaught
process.on('uncaughtException', (e) => {
  console.error('uncaught:', e);
  process.exit(1);
});