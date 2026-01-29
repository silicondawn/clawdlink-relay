#!/usr/bin/env node
'use strict';

const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const WebSocket = require('ws');
const http = require('http');

const RELAY = 'ws://127.0.0.1:19900';
const HTTP_BASE = 'http://127.0.0.1:19900';

function makeKeypair() {
  const kp = nacl.sign.keyPair();
  return {
    publicKey: naclUtil.encodeBase64(kp.publicKey),
    secretKey: kp.secretKey,
    fullKey: `ed25519:${naclUtil.encodeBase64(kp.publicKey)}`,
  };
}

function sign(secretKey, message) {
  const msgBytes = naclUtil.decodeUTF8(message);
  const sig = nacl.sign.detached(msgBytes, secretKey);
  return naclUtil.encodeBase64(sig);
}

function httpPost(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(`${HTTP_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
    }, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(buf) }); }
        catch { resolve({ status: res.statusCode, body: buf }); }
      });
    });
    req.on('error', reject);
    req.end(data);
  });
}

function httpGet(path) {
  return new Promise((resolve, reject) => {
    http.get(`${HTTP_BASE}${path}`, (res) => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(buf) }); }
        catch { resolve({ status: res.statusCode, body: buf }); }
      });
    }).on('error', reject);
  });
}

function connectWs(keypair) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(RELAY);
    const msgs = [];
    ws.on('open', () => {
      const ts = String(Math.floor(Date.now() / 1000));
      const authMsg = `auth:${keypair.fullKey}:${ts}`;
      const signature = sign(keypair.secretKey, authMsg);
      ws.send(JSON.stringify({ type: 'auth', key: keypair.fullKey, timestamp: ts, signature }));
    });
    ws.on('message', (data) => {
      const msg = JSON.parse(data);
      msgs.push(msg);
      if (msg.type === 'auth_ok') resolve({ ws, msgs, keypair });
      if (msg.type === 'error' && msg.code === 'auth_failed') reject(new Error('Auth failed'));
    });
    ws.on('error', reject);
  });
}

function waitMsg(msgs, type, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const check = () => {
      const found = msgs.find(m => m.type === type);
      if (found) return resolve(found);
      if (Date.now() - start > timeoutMs) return reject(new Error(`Timeout waiting for ${type}`));
      setTimeout(check, 100);
    };
    check();
  });
}

let passed = 0, failed = 0;
function assert(cond, label) {
  if (cond) { console.log(`  ✅ ${label}`); passed++; }
  else { console.log(`  ❌ ${label}`); failed++; }
}

async function run() {
  console.log('=== ClawdLink Relay Tests ===\n');

  // 1. Health check
  console.log('1. Health check');
  const health = await httpGet('/health');
  assert(health.status === 200 && health.body.status === 'ok', 'GET /health returns ok');

  // 2. WebSocket auth
  console.log('\n2. WebSocket auth');
  const alice = makeKeypair();
  const bob = makeKeypair();
  const a = await connectWs(alice);
  assert(a.msgs.some(m => m.type === 'auth_ok'), 'Alice authenticated');
  const b = await connectWs(bob);
  assert(b.msgs.some(m => m.type === 'auth_ok'), 'Bob authenticated');

  // 3. Message without friendship → error
  console.log('\n3. Message without friendship');
  const msgPayload = { type: 'message', to: bob.fullKey, ciphertext: 'hello', nonce: 'n1' };
  const msgSig = sign(alice.secretKey, JSON.stringify(msgPayload));
  a.ws.send(JSON.stringify({ ...msgPayload, signature: msgSig }));
  const err = await waitMsg(a.msgs, 'error');
  assert(err.code === 'not_friends', 'Blocked: not_friends');

  // 4. Friend request
  console.log('\n4. Friend request flow');
  const frPayload = { type: 'friend_request', to: bob.fullKey, name: 'Alice' };
  const frSig = sign(alice.secretKey, JSON.stringify(frPayload));
  a.ws.send(JSON.stringify({ ...frPayload, signature: frSig }));
  const frMsg = await waitMsg(b.msgs, 'friend_request');
  assert(frMsg.from === alice.fullKey, 'Bob received friend request from Alice');

  // 5. Friend accept
  const faPayload = { type: 'friend_accept', to: alice.fullKey, name: 'Bob' };
  const faSig = sign(bob.secretKey, JSON.stringify(faPayload));
  b.ws.send(JSON.stringify({ ...faPayload, signature: faSig }));
  const faMsg = await waitMsg(a.msgs, 'friend_accepted');
  assert(faMsg.from === bob.fullKey, 'Alice received friend_accepted from Bob');

  // 6. Send message (now friends)
  console.log('\n5. Message after friendship');
  const msg2 = { type: 'message', to: bob.fullKey, ciphertext: 'encrypted_hello', nonce: 'n2' };
  const msg2Sig = sign(alice.secretKey, JSON.stringify(msg2));
  a.ws.send(JSON.stringify({ ...msg2, signature: msg2Sig }));
  const delivered = await waitMsg(b.msgs, 'message');
  assert(delivered.from === alice.fullKey && delivered.ciphertext === 'encrypted_hello', 'Bob received message from Alice');

  // 7. Offline message
  console.log('\n6. Offline message');
  b.ws.close();
  await new Promise(r => setTimeout(r, 500));
  const msg3 = { type: 'message', to: bob.fullKey, ciphertext: 'offline_msg', nonce: 'n3' };
  const msg3Sig = sign(alice.secretKey, JSON.stringify(msg3));
  a.ws.send(JSON.stringify({ ...msg3, signature: msg3Sig }));
  await new Promise(r => setTimeout(r, 500));
  // Bob reconnects
  const b2 = await connectWs(bob);
  const offlineMsgs = await waitMsg(b2.msgs, 'offline_messages');
  assert(offlineMsgs.messages.length >= 1 && offlineMsgs.messages[0].ciphertext === 'offline_msg', 'Bob received offline message on reconnect');

  // Cleanup
  a.ws.close();
  b2.ws.close();

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch(e => { console.error(e); process.exit(1); });
