# ClawdLink Relay Server

本地中继服务器，WebSocket 实时通信 + HTTP 降级，Ed25519 签名验证，好友机制，离线消息。

## 快速部署

```bash
cd /home/yibo/clawd/clawdlink-relay
npm install
node server.js
```

## 配置

环境变量：
| 变量 | 默认值 | 说明 |
|------|--------|------|
| `RELAY_PORT` | 19900 | 监听端口 |
| `RELAY_HOST` | 0.0.0.0 | 监听地址 |
| `RELAY_DB` | ./relay.db | SQLite 数据库路径 |

## Systemd 部署

```bash
# 用户级 service
mkdir -p ~/.config/systemd/user
cp clawdlink-relay.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now clawdlink-relay
systemctl --user status clawdlink-relay

# 查看日志
journalctl --user -u clawdlink-relay -f
```

## 在 01/02 上切换 Relay 地址

01 (本机) 上的客户端连接：
```
ws://127.0.0.1:19900
```

02 (10.0.0.3 → 连接 01) 上的客户端连接：
```
ws://10.0.0.1:19900   # 或 01 的内网 IP
```

### 客户端 relay.js 改动

在 ClawdLink 客户端的 `relay.js` 中修改：
```js
// 旧: const RELAY_URL = 'wss://some-cloud-relay.example.com';
// 新:
const RELAY_URL = process.env.CLAWDLINK_RELAY || 'ws://127.0.0.1:19900';
```

HTTP 降级地址同理：
```js
const RELAY_HTTP = process.env.CLAWDLINK_RELAY_HTTP || 'http://127.0.0.1:19900';
```

## API 端点

### WebSocket (`ws://host:19900`)

连接后发送 auth 消息：
```json
{"type": "auth", "key": "ed25519:BASE64...", "timestamp": "UNIX_TS", "signature": "BASE64..."}
```

签名内容：`auth:ed25519:KEY:TIMESTAMP`

### HTTP 降级

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /health | 健康检查 |
| POST | /send | 发送消息 |
| GET | /poll | 拉取离线消息 |
| POST | /friend-request | 发送好友请求 |
| POST | /friend-accept | 接受好友请求 |

## 好友管理

通过 WebSocket 或 HTTP：

```json
// 发送好友请求
{"type": "friend_request", "to": "ed25519:BOB_KEY", "name": "Alice", "signature": "..."}

// 接受好友请求
{"type": "friend_accept", "to": "ed25519:ALICE_KEY", "name": "Bob", "signature": "..."}
```

签名内容分别为完整 JSON 对象（不含 signature 字段）的 stringify。

## 故障排查

```bash
# 检查服务状态
systemctl --user status clawdlink-relay

# 检查端口
ss -tlnp | grep 19900

# 检查数据库
sqlite3 relay.db "SELECT COUNT(*) FROM friendships WHERE status='accepted';"
sqlite3 relay.db "SELECT COUNT(*) FROM messages;"

# 手动健康检查
curl http://127.0.0.1:19900/health

# 清理过期消息（服务会自动清理，也可手动）
sqlite3 relay.db "DELETE FROM messages WHERE expires_at <= strftime('%s','now');"
```

## 测试

```bash
# 启动服务后运行测试
node test.js
```
