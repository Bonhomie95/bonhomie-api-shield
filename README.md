# 🛡️ @bonhomie/api-shield

### **The Ultimate Security & Utility Toolkit for Node.js APIs**

**Rate limiting, fingerprinting, CSRF, JWT, bot detection, RBAC, sanitization, attack detection, caching, cron helpers & more.**

[![npm version](https://img.shields.io/npm/v/@bonhomie/api-shield.svg?color=blue)](https://www.npmjs.com/package/@bonhomie/api-shield)
[![npm downloads](https://img.shields.io/npm/dm/@bonhomie/api-shield.svg?color=brightgreen)](https://www.npmjs.com/package/@bonhomie/api-shield)
![node-current](https://img.shields.io/node/v/@bonhomie/api-shield)
![license](https://img.shields.io/badge/license-MIT-green)
![security](https://img.shields.io/badge/security-hardened-critical)

---

## 🚀 Why API Shield?

`@bonhomie/api-shield` is an **all-in-one backend security and utility layer** designed for **Express, Fastify, or any Node.js API**.

It provides:

* 🔐 **JWT auth** (sign, verify, attach user, roles)
* 🛡 **CSRF protection** (double-submit cookie)
* 🧪 **Input validation + sanitization**
* ⚔️ **SQLi/XSS/path-traversal detection**
* 🕵️ **Bot detection + device fingerprinting**
* 🚦 **Rate limiting (memory & Redis)**
* 🔄 **Cache wrapper (Redis + in-memory)**
* 🧰 **Password hashing (argon2)**
* 🕹 **RBAC (roles + permissions)**
* 📅 **Cron helpers**
* 📦 **Response formatters (success, fail, paginate)**
* 🌐 **HMAC, nonce, and anti-replay tokens**

Everything packaged cleanly and production-ready.

---

# 📦 Installation

```bash
npm install @bonhomie/api-shield
```

Requires Node 18+.

---

# ⚡ Quick Start (Express)

```js
import express from "express";
import cookieParser from "cookie-parser";
import {
  requestLogger,
  attackGuard,
  sanitizeRequest,
  csrfCookie,
  csrfProtect,
  createRateLimiter,
  requireAuth,
} from "@bonhomie/api-shield";

const app = express();
app.use(express.json());
app.use(cookieParser());

// Global protections
app.use(requestLogger());
app.use(attackGuard({ block: true }));
app.use(sanitizeRequest());
app.use(csrfCookie());

// Rate limiter
const limiter = createRateLimiter({ limit: 100, windowMs: 60000 });
app.use(limiter);

// Protected route
app.post("/update-profile",
  csrfProtect(),
  requireAuth({ secret: process.env.JWT_SECRET }),
  (req, res) => {
    res.success({ message: "Profile updated" });
  }
);

app.listen(3000);
```

---

# 🔐 JWT Utilities

```js
import { signJwt, requireAuth } from "@bonhomie/api-shield";

const token = signJwt(
  { id: user._id, role: "admin" },
  { secret: process.env.JWT_SECRET, expiresIn: "15m" }
);

app.get("/admin",
  requireAuth({
    secret: process.env.JWT_SECRET,
    roles: ["admin"]
  }),
  (req, res) => res.success("Welcome Admin")
);
```

---

# 🛡 CSRF Protection (double-submit cookie)

```js
import { csrfCookie, csrfProtect } from "@bonhomie/api-shield";

app.use(csrfCookie());

app.post("/form",
  csrfProtect(),
  (req, res) => res.success("Submitted")
);
```

Frontend must include the CSRF token:

```
Header: x-csrf-token: <token_from_cookie>
```

---

# 🔐 Password Hashing (argon2)

```js
import { hashPassword, verifyPassword } from "@bonhomie/api-shield";

const hash = await hashPassword("password123");
const ok = await verifyPassword("password123", hash);
```

---

# ⚙ Input Sanitization

```js
import { sanitizeRequest } from "@bonhomie/api-shield";

app.use(sanitizeRequest());
```

Cleans `req.body`, `req.query`, and `req.params` from XSS.

---

# ⚔ SQLi / XSS Attack Detection

```js
import { attackGuard } from "@bonhomie/api-shield";

app.use(attackGuard({ block: true }));
```

Automatically blocks dangerous payloads.

---

# 🕵️ Bot Detection + Device Fingerprinting

```js
import { botGuard, fingerprintV2 } from "@bonhomie/api-shield";

app.use(botGuard({ block: false }));
```

Detects:

* Bad user-agent patterns
* Scripted bots
* Headless browsers

Fingerprint v2 uses:

* IP
* User-Agent
* Accept-Language
* Screen/device hints

---

# 🚦 Rate Limiting (Memory or Redis)

```js
import { createRateLimiter } from "@bonhomie/api-shield";

const limiter = createRateLimiter({
  limit: 100,
  windowMs: 60000
});

app.use(limiter);
```

Redis version:

```js
createRateLimiter({ redis, limit: 100, windowMs: 60000 });
```

---

# 🧰 Response Formatters

```js
import { success, fail, paginate } from "@bonhomie/api-shield";

res.json(success({ name: "Bonhomie" }));
res.json(fail("Unauthorized", 401));
res.json(paginate(items, { page: 1, perPage: 10, total: 200 }));
```

Or attach directly:

```js
import { responseFormatter } from "@bonhomie/api-shield";

app.use(responseFormatter());

res.success({ msg: "OK" });
res.fail("Oops");
```

---

# 🔄 Cache Wrapper (Redis or Memory)

```js
import { cache } from "@bonhomie/api-shield";

await cache.set("profile:123", { name: "Bonhomie" }, 60000);
const data = await cache.get("profile:123");
```

Works with Redis or in-memory fallback.

---

# 🔧 Cron Helpers

```js
import { cronEvery, cronAt } from "@bonhomie/api-shield";

cronEvery("5m", () => console.log("runs every 5 minutes"));
cronAt("0 0 * * *", () => console.log("midnight job"));
```

---

# 🛂 RBAC (Roles & Permissions)

```js
import { requireRole, requirePermission } from "@bonhomie/api-shield";

app.get("/admin",
  requireRole(["admin"]),
  (req, res) => res.success("Admin Panel")
);

app.post("/edit",
  requirePermission("edit:content"),
  (req, res) => res.success("Updated")
);
```

---

# 🧬 Replay Protection + HMAC + Nonce

```js
import {
  createReplayToken,
  createHmac,
  verifyHmac,
  generateNonce
} from "@bonhomie/api-shield";

const token = createReplayToken();
const nonce = generateNonce();
const signature = createHmac(secret, payload);
```

---

# 🛠 Developer-Friendly Features

* Zero configuration needed
* ESM-first
* Works in Express, Fastify, NestJS, or raw Node
* Lightweight single-file build
* Safe defaults
* Production security baked in

---

# 🔍 SEO Keywords

> (This helps your npm ranking)

```
node api security, csrf token express, node jwt middleware, express rate limiter,
node sanitizer, api shield, bot detection node, argon2 password hashing,
nodejs validation, node hmac, express anti replay, security middleware node,
xss sqli detection node, rbac nodejs, redis caching node
```

---
# 📄 License

MIT © Bonhomie
---

# ❤️ Contribute
Pull requests welcome.
Security suggestions extra welcome.