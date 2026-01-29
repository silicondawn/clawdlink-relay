#!/usr/bin/env node
'use strict';

const WebSocket = require('ws');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const fs = require('fs');
const path = require('path');
const http = require('http');

// --- Config ---
const RELAY_WS_URL = process.env.RELAY_WS_URL || 'ws://127.0.0.1:19900';
const GATEWAY_URL = process.env.GATEWAY_URL || 'http://127.0.0.1:18789';
const GATEWAY_TOKEN = process.env.GATEWAY_TOKEN;
const IDENTITY_PATH = path.join(process.env.HOME, '.clawdbot/clawdlink/identity.json');
const FRIENDS_PATH = path.join(process.env.HOME, '.clawdbot/clawdlink/friends.json');
const RECONNECT_DELAY = 5000;
const PING_INTERVAL = 30000;

if (!GATEWAY_TOKEN) {
  console.error('GATEWAY_TOKEN env required');
  process.exit(1);
}

// --- Identity ---
const identity = JSON.parse(fs.readFileSync(IDENTITY_PATH, 'utf-8'));
const secretKeyBytes = naclUtil.decodeBase64(identity.secretKey);
const publicKeyBytes = naclUtil.decodeBase64(identity.publicKey);

// --- Helpers ---
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function base64ToHex(b64) {
  return bytesToHex(naclUtil.decodeBase64(b64));
}

function loadFriends() {
  try {
    return JSON.parse(fs.readFileSync(FRIENDS_PATH, 'utf-8')).friends || [];
  } catch {
    return [];
  }
}

function findFriendByHexKey(hexKey) {
  const friends = loadFriends();
  const needle = hexKey.toLowerCase();
  return friends.find(f => base64ToHex(f.publicKey).toLowerCase() === needle);
}

// --- Gateway tools/invoke API ---
function sendNotification(message) {
  // Inject into dedicated ClawdLink session (isolated from main chat)
  // Fire-and-forget: set a short timeout so daemon doesn't block
  const body = JSON.stringify({
    tool: 'sessions_send',
    args: { message, label: 'clawdlink', timeoutSeconds: 10 }
  });
  const urlObj = new URL('/tools/invoke', GATEWAY_URL);
  const options = {
    hostname: urlObj.hostname,
    port: urlObj.port,
    path: urlObj.pathname,
    method: 'POST',
    timeout: 10000,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${GATEWAY_TOKEN}`,
      'Content-Length': Buffer.byteLength(body),
    },
  };
  const req = http.request(options, (res) => {
    let data = '';
    res.on('data', c => data += c);
    res.on('end', () => {
      if (res.statusCode !== 200) {
        console.error(`Gateway ${res.statusCode}: ${data}`);
      } else {
        console.log('Injected into agent session');
      }
    });
  });
  req.on('timeout', () => {
    console.log('Gateway request timeout (agent processing async)');
    req.destroy();
  });
  req.on('error', e => {
    if (e.code !== 'ECONNRESET') console.error('Gateway error:', e.message);
  });
  req.write(body);
  req.end();
}

// --- Decrypt message ---
function decryptMessage(ciphertext, nonce, sharedSecret) {
  const ct = naclUtil.decodeBase64(ciphertext);
  const n = naclUtil.decodeBase64(nonce);
  const key = naclUtil.decodeBase64(sharedSecret);
  const plain = nacl.secretbox.open(ct, n, key);
  if (!plain) return null;
  return naclUtil.encodeUTF8(plain);
}

// --- Auth ---
function buildAuthMessage() {
  const hexPub = bytesToHex(publicKeyBytes);
  const keyStr = `ed25519:${hexPub}`;
  const timestamp = String(Math.floor(Date.now() / 1000));
  const authStr = `auth:${keyStr}:${timestamp}`;
  const sig = nacl.sign.detached(naclUtil.decodeUTF8(authStr), secretKeyBytes);
  return { type: 'auth', key: keyStr, timestamp, signature: bytesToHex(sig) };
}

// --- WebSocket connection ---
let ws = null;
let pingTimer = null;
let reconnectTimer = null;

function connect() {
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  
  console.log(`Connecting to ${RELAY_WS_URL}...`);
  ws = new WebSocket(RELAY_WS_URL);

  ws.on('open', () => {
    console.log('Connected, authenticating...');
    ws.send(JSON.stringify(buildAuthMessage()));
    
    // Ping keepalive
    if (pingTimer) clearInterval(pingTimer);
    pingTimer = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.ping();
    }, PING_INTERVAL);
  });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return console.error('Bad JSON:', raw.toString()); }

    if (msg.type === 'auth_ok') {
      console.log('Authenticated successfully');
      return;
    }

    if (msg.type === 'error') {
      console.error('Relay error:', msg.code, msg.message);
      return;
    }

    if (msg.type === 'message') {
      handleMessage(msg);
      return;
    }

    if (msg.type === 'offline_messages') {
      console.log(`Received ${msg.messages.length} offline messages`);
      for (const m of msg.messages) handleMessage(m);
      return;
    }

    if (msg.type === 'friend_request') {
      const name = msg.name || msg.from || 'unknown';
      console.log(`Friend request from: ${name}`);
      sendNotification(`🤝 ClawdLink friend request from ${name} (key: ${msg.from})`);
      return;
    }

    if (msg.type === 'friend_accepted') {
      const name = msg.name || msg.from || 'unknown';
      console.log(`Friend accepted: ${name}`);
      sendNotification(`✅ ClawdLink friend accepted: ${name}`);
      return;
    }

    console.log('Unknown message type:', msg.type);
  });

  ws.on('close', (code, reason) => {
    console.log(`Disconnected (${code}), reconnecting in ${RECONNECT_DELAY}ms...`);
    cleanup();
    reconnectTimer = setTimeout(connect, RECONNECT_DELAY);
  });

  ws.on('error', (err) => {
    console.error('WS error:', err.message);
  });
}

function handleMessage(msg) {
  const fromHex = msg.from;
  const friend = findFriendByHexKey(fromHex);
  const name = friend ? friend.displayName : fromHex.slice(0, 12) + '...';

  if (!friend) {
    console.log(`Message from unknown key: ${fromHex}`);
    sendNotification(`📨 ClawdLink from unknown (${fromHex.slice(0, 16)}...): [no shared key to decrypt]`);
    return;
  }

  const text = decryptMessage(msg.ciphertext, msg.nonce, friend.sharedSecret);
  if (!text) {
    console.error(`Failed to decrypt message from ${name}`);
    sendNotification(`📨 ClawdLink from ${name}: [decryption failed]`);
    return;
  }

  console.log(`Message from ${name}: ${text}`);
  // Parse the decrypted content - it's JSON with .text field
  let displayText = text;
  try {
    const parsed = JSON.parse(text);
    if (parsed.text) displayText = parsed.text;
  } catch {}
  sendNotification(`[ClawdLink] ${name}: ${displayText}`);
}

function cleanup() {
  if (pingTimer) { clearInterval(pingTimer); pingTimer = null; }
  ws = null;
}

// --- Start ---
connect();

process.on('SIGTERM', () => {
  console.log('SIGTERM, shutting down...');
  if (ws) ws.close();
  cleanup();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT, shutting down...');
  if (ws) ws.close();
  cleanup();
  process.exit(0);
});
