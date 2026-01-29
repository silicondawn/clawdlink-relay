#!/usr/bin/env node
'use strict';

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');
const path = require('path');

// --- Config ---
const PORT = process.env.RELAY_PORT || 19900;
const HOST = process.env.RELAY_HOST || '0.0.0.0';
const DB_PATH = process.env.RELAY_DB || path.join(__dirname, 'relay.db');
const OFFLINE_TTL = 7 * 24 * 3600; // 7 days
const HEARTBEAT_INTERVAL = 30000;
const FRIEND_REQ_LIMIT = 10; // per key per hour

// --- Database ---
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS friendships (
    key_a TEXT NOT NULL,
    key_b TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at INTEGER DEFAULT (strftime('%s','now')),
    PRIMARY KEY (key_a, key_b)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_key TEXT NOT NULL,
    to_key TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    expires_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_key TEXT NOT NULL,
    to_key TEXT NOT NULL,
    from_name TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_key);
  CREATE INDEX IF NOT EXISTS idx_friendships_pair ON friendships(key_a, key_b);
`);

// Prepared statements
const stmts = {
  areFriends: db.prepare(`
    SELECT 1 FROM friendships
    WHERE ((key_a = ? AND key_b = ?) OR (key_a = ? AND key_b = ?))
    AND status = 'accepted' LIMIT 1
  `),
  insertFriendship: db.prepare(`
    INSERT OR IGNORE INTO friendships (key_a, key_b, status) VALUES (?, ?, 'pending')
  `),
  acceptFriendship: db.prepare(`
    UPDATE friendships SET status = 'accepted'
    WHERE key_a = ? AND key_b = ? AND status = 'pending'
  `),
  insertReverseFriendship: db.prepare(`
    INSERT OR REPLACE INTO friendships (key_a, key_b, status) VALUES (?, ?, 'accepted')
  `),
  insertFriendRequest: db.prepare(`
    INSERT INTO friend_requests (from_key, to_key, from_name) VALUES (?, ?, ?)
  `),
  getPendingRequests: db.prepare(`
    SELECT * FROM friend_requests WHERE to_key = ? ORDER BY created_at ASC
  `),
  deleteFriendRequests: db.prepare(`
    DELETE FROM friend_requests WHERE from_key = ? AND to_key = ?
  `),
  countRecentRequests: db.prepare(`
    SELECT COUNT(*) as cnt FROM friend_requests
    WHERE from_key = ? AND created_at > ?
  `),
  storeMessage: db.prepare(`
    INSERT INTO messages (from_key, to_key, payload, expires_at)
    VALUES (?, ?, ?, ?)
  `),
  getOfflineMessages: db.prepare(`
    SELECT * FROM messages WHERE to_key = ? AND expires_at > ? ORDER BY created_at ASC
  `),
  deleteMessages: db.prepare(`
    DELETE FROM messages WHERE to_key = ?
  `),
  cleanExpired: db.prepare(`
    DELETE FROM messages WHERE expires_at <= ?
  `),
};

// --- Helpers ---
// Internally store keys with ed25519: prefix
function canonicalKey(key) {
  if (!key) return key;
  return key.startsWith('ed25519:') ? key : `ed25519:${key}`;
}

// Strip prefix for outbound messages (original relay sends bare hex)
function bareKey(key) {
  return key.startsWith('ed25519:') ? key.slice(8) : key;
}

function areFriends(a, b) {
  const ka = canonicalKey(a), kb = canonicalKey(b);
  return !!stmts.areFriends.get(ka, kb, kb, ka);
}

function now() {
  return Math.floor(Date.now() / 1000);
}

// Verify Ed25519 signature. Key and signature can be hex or base64.
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function decodeKey(key) {
  const raw = key.startsWith('ed25519:') ? key.slice(8) : key;
  // Detect hex (64 chars = 32 bytes) vs base64
  if (/^[0-9a-f]+$/i.test(raw) && raw.length === 64) {
    return hexToBytes(raw);
  }
  return naclUtil.decodeBase64(raw);
}

function decodeSig(sig) {
  if (/^[0-9a-f]+$/i.test(sig) && sig.length === 128) {
    return hexToBytes(sig);
  }
  return naclUtil.decodeBase64(sig);
}

// --- Online clients ---
const clients = new Map(); // key -> ws

// --- Express + HTTP fallback ---
const app = express();
app.use(express.json());

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', clients: clients.size, uptime: process.uptime() });
});

// HTTP: send message
// Compatible with original ClawdLink client which sends:
//   { from: "ed25519:HEX", to: "ed25519:HEX", ciphertext, nonce, signature: "HEX" }
//   where signature = sign(ciphertext_bytes, secretKey) — NOT a JSON string
app.post('/send', (req, res) => {
  const from = req.body.from || req.body.key;
  const { to, ciphertext, nonce, signature } = req.body;
  if (!from || !to || !ciphertext || !signature) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  const fromKey = canonicalKey(from), toKey = canonicalKey(to);
  if (!areFriends(fromKey, toKey)) {
    return res.status(403).json({ error: 'not_friends' });
  }
  // Store/deliver (relay trusts E2E encryption for integrity)
  const payload = JSON.stringify({ from: bareKey(fromKey), ciphertext, nonce, signature });
  const targetWs = clients.get(toKey);
  if (targetWs && targetWs.readyState === 1) {
    targetWs.send(JSON.stringify({ type: 'message', from: bareKey(fromKey), ciphertext, nonce, signature }));
    return res.json({ delivered: true });
  }
  stmts.storeMessage.run(fromKey, toKey, payload, now() + OFFLINE_TTL);
  res.json({ delivered: false, queued: true });
});

// HTTP: poll messages
// Compatible with original client which sends via headers:
//   X-ClawdLink-Key, X-ClawdLink-Timestamp, X-ClawdLink-Signature
app.get('/poll', (req, res) => {
  const key = req.headers['x-clawdlink-key'] || req.query.key;
  const timestamp = req.headers['x-clawdlink-timestamp'] || req.query.timestamp;
  const signature = req.headers['x-clawdlink-signature'] || req.query.signature;
  if (!key) return res.status(400).json({ error: 'missing_fields' });
  
  // Verify signature if provided
  if (signature && timestamp) {
    try {
      const msg = `poll:${timestamp}`;
      const pubKey = decodeKey(key);
      const sig = decodeSig(signature);
      const msgBytes = naclUtil.decodeUTF8(msg);
      if (!nacl.sign.detached.verify(msgBytes, sig, pubKey)) {
        return res.status(401).json({ error: 'invalid_signature' });
      }
    } catch {
      return res.status(401).json({ error: 'invalid_signature' });
    }
  }
  
  const k = canonicalKey(key);
  const messages = stmts.getOfflineMessages.all(k, now());
  stmts.deleteMessages.run(k);
  const pendingReqs = stmts.getPendingRequests.all(k);
  res.json({ messages: messages.map(m => JSON.parse(m.payload)), friend_requests: pendingReqs });
});

// HTTP: GET friend requests (compatibility with original client which calls /requests)
app.get('/requests', (req, res) => {
  const key = req.headers['x-clawdlink-key'] || req.query.key;
  if (!key) return res.status(400).json({ error: 'missing_fields' });
  const k = canonicalKey(key);
  const pendingReqs = stmts.getPendingRequests.all(k);
  res.json({ requests: pendingReqs });
});

// HTTP: friend request
app.post('/friend-request', (req, res) => {
  const from = req.body.from || req.body.key;
  const { to, name } = req.body;
  if (!from || !to) return res.status(400).json({ error: 'missing_fields' });
  const fromKey = canonicalKey(from), toKey = canonicalKey(to);
  // Rate limit
  const hourAgo = now() - 3600;
  const { cnt } = stmts.countRecentRequests.get(fromKey, hourAgo);
  if (cnt >= FRIEND_REQ_LIMIT) {
    return res.status(429).json({ error: 'rate_limited' });
  }
  stmts.insertFriendship.run(fromKey, toKey, 'pending');
  stmts.insertFriendRequest.run(fromKey, toKey, name || null);
  // Push if online
  const targetWs = clients.get(toKey);
  if (targetWs && targetWs.readyState === 1) {
    targetWs.send(JSON.stringify({ type: 'friend_request', from: bareKey(fromKey), name: name || '' }));
  }
  res.json({ ok: true });
});

// HTTP: friend accept
app.post('/friend-accept', (req, res) => {
  const from = req.body.from || req.body.key;
  const { to, name } = req.body;
  if (!from || !to) return res.status(400).json({ error: 'missing_fields' });
  const fromKey = canonicalKey(from), toKey = canonicalKey(to);
  // Accept: toKey sent request to fromKey → friendship(toKey, fromKey) pending
  const changed = stmts.acceptFriendship.run(toKey, fromKey);
  if (changed.changes === 0) {
    return res.status(404).json({ error: 'no_pending_request' });
  }
  stmts.insertReverseFriendship.run(fromKey, toKey);
  stmts.deleteFriendRequests.run(toKey, fromKey);
  // Notify
  const targetWs = clients.get(toKey);
  if (targetWs && targetWs.readyState === 1) {
    targetWs.send(JSON.stringify({ type: 'friend_accepted', from: bareKey(fromKey), name: name || '' }));
  }
  res.json({ ok: true });
});

// --- HTTP Server + WebSocket ---
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.authKey = null;

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return ws.send(JSON.stringify({ type: 'error', code: 'invalid_json', message: 'Invalid JSON' })); }

    // --- Auth ---
    if (msg.type === 'auth') {
      const { key, timestamp, signature } = msg;
      if (!key || !timestamp || !signature) {
        return ws.send(JSON.stringify({ type: 'error', code: 'missing_fields', message: 'Missing auth fields' }));
      }
      const ts = parseInt(timestamp, 10);
      if (Math.abs(now() - ts) > 300) {
        return ws.send(JSON.stringify({ type: 'error', code: 'expired', message: 'Auth timestamp expired' }));
      }
      try {
        const authMsg = `auth:${key}:${timestamp}`;
        const pubKey = decodeKey(key);
        const sig = decodeSig(signature);
        const msgBytes = naclUtil.decodeUTF8(authMsg);
        if (!nacl.sign.detached.verify(msgBytes, sig, pubKey)) {
          return ws.send(JSON.stringify({ type: 'error', code: 'auth_failed', message: 'Signature verification failed' }));
        }
      } catch {
        return ws.send(JSON.stringify({ type: 'error', code: 'auth_failed', message: 'Signature verification failed' }));
      }
      const k = canonicalKey(key);
      ws.authKey = k;
      const old = clients.get(k);
      if (old && old !== ws) { old.close(1000, 'replaced'); }
      clients.set(k, ws);
      ws.send(JSON.stringify({ type: 'auth_ok' }));

      // Deliver offline messages
      const offMsgs = stmts.getOfflineMessages.all(k, now());
      if (offMsgs.length > 0) {
        ws.send(JSON.stringify({ type: 'offline_messages', messages: offMsgs.map(m => JSON.parse(m.payload)) }));
        stmts.deleteMessages.run(k);
      }
      // Deliver pending friend requests
      const pendingReqs = stmts.getPendingRequests.all(k);
      for (const r of pendingReqs) {
        ws.send(JSON.stringify({ type: 'friend_request', from: r.from_key, name: r.from_name || '' }));
      }
      return;
    }

    // All other messages require auth
    if (!ws.authKey) {
      return ws.send(JSON.stringify({ type: 'error', code: 'not_authenticated', message: 'Auth required' }));
    }

    // --- Message ---
    if (msg.type === 'message') {
      const { to, ciphertext, nonce, signature } = msg;
      if (!to || !ciphertext) {
        return ws.send(JSON.stringify({ type: 'error', code: 'missing_fields', message: 'Missing message fields' }));
      }
      const toKey = canonicalKey(to);
      if (!areFriends(ws.authKey, toKey)) {
        return ws.send(JSON.stringify({ type: 'error', code: 'not_friends', message: 'You are not friends with this user' }));
      }
      const outMsg = { type: 'message', from: bareKey(ws.authKey), ciphertext, nonce, signature };
      const targetWs = clients.get(toKey);
      if (targetWs && targetWs.readyState === 1) {
        targetWs.send(JSON.stringify(outMsg));
      } else {
        stmts.storeMessage.run(ws.authKey, toKey, JSON.stringify(outMsg), now() + OFFLINE_TTL);
      }
      return;
    }

    // --- Friend Request ---
    if (msg.type === 'friend_request') {
      const { to, name } = msg;
      if (!to) {
        return ws.send(JSON.stringify({ type: 'error', code: 'missing_fields', message: 'Missing fields' }));
      }
      const toKey = canonicalKey(to);
      const hourAgo = now() - 3600;
      const { cnt } = stmts.countRecentRequests.get(ws.authKey, hourAgo);
      if (cnt >= FRIEND_REQ_LIMIT) {
        return ws.send(JSON.stringify({ type: 'error', code: 'rate_limited', message: 'Too many friend requests' }));
      }
      stmts.insertFriendship.run(ws.authKey, toKey);
      stmts.insertFriendRequest.run(ws.authKey, toKey, name || null);
      const targetWs = clients.get(toKey);
      if (targetWs && targetWs.readyState === 1) {
        targetWs.send(JSON.stringify({ type: 'friend_request', from: bareKey(ws.authKey), name: name || '' }));
      }
      ws.send(JSON.stringify({ type: 'friend_request_sent', to: toKey }));
      return;
    }

    // --- Friend Accept ---
    if (msg.type === 'friend_accept') {
      const { to, name } = msg;
      if (!to) {
        return ws.send(JSON.stringify({ type: 'error', code: 'missing_fields', message: 'Missing fields' }));
      }
      const toKey = canonicalKey(to);
      const changed = stmts.acceptFriendship.run(toKey, ws.authKey);
      if (changed.changes === 0) {
        return ws.send(JSON.stringify({ type: 'error', code: 'no_pending_request', message: 'No pending request from this user' }));
      }
      stmts.insertReverseFriendship.run(ws.authKey, toKey);
      stmts.deleteFriendRequests.run(toKey, ws.authKey);
      const targetWs = clients.get(toKey);
      if (targetWs && targetWs.readyState === 1) {
        targetWs.send(JSON.stringify({ type: 'friend_accepted', from: bareKey(ws.authKey), name: name || '' }));
      }
      ws.send(JSON.stringify({ type: 'friend_accept_ok', to: toKey }));
      return;
    }

    ws.send(JSON.stringify({ type: 'error', code: 'unknown_type', message: `Unknown message type: ${msg.type}` }));
  });

  ws.on('close', () => {
    if (ws.authKey && clients.get(ws.authKey) === ws) {
      clients.delete(ws.authKey);
    }
  });
});

// Heartbeat
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, HEARTBEAT_INTERVAL);

// Cleanup expired messages every hour
const cleanup = setInterval(() => {
  stmts.cleanExpired.run(now());
}, 3600000);

wss.on('close', () => {
  clearInterval(heartbeat);
  clearInterval(cleanup);
});

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down...');
  wss.close();
  server.close();
  db.close();
  process.exit(0);
});

server.listen(PORT, HOST, () => {
  console.log(`ClawdLink Relay listening on ${HOST}:${PORT}`);
  console.log(`Database: ${DB_PATH}`);
});
