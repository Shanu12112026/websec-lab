// ⚠️  INTENTIONALLY VULNERABLE — for security training only. Never deploy publicly.
const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

// --- in-memory state ---
const users = {
  admin: { password: "admin123", balance: 1000, role: "admin" },
};
const comments = [
  { id: 1, author: "alice", body: "Welcome to the board!" },
  { id: 2, author: "bob", body: "Hello everyone." },
];
const sessions = {}; // token -> username

// --- helpers ---
function getSession(req) {
  const token = req.cookies ? req.cookies.sid : req.headers.cookie?.match(/sid=([^;]+)/)?.[1];
  if (token && sessions[token]) return { token, user: sessions[token] };
  return null;
}

// parse cookies (minimal, no hardening)
app.use((req, _res, next) => {
  req.cookies = {};
  (req.headers.cookie || "").split(";").forEach((p) => {
    const [k, ...v] = p.trim().split("=");
    if (k) req.cookies[k] = decodeURIComponent(v.join("="));
  });
  next();
});

// 🐛 BUG #1 (CORS): reflects any Origin header and allows credentials.
app.use((req, res, next) => {
  if (req.headers.origin) {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// --- auth ---
app.get("/login", (_req, res) => {
  res.send(`<html><body>
    <h1>Login</h1>
    <form method="POST" action="/login">
      <input name="username" placeholder="username">
      <input name="password" type="password" placeholder="password">
      <button>Login</button>
    </form>
  </body></html>`);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const u = users[username];
  if (!u || u.password !== password) return res.status(401).send("Invalid credentials");
  const token = crypto.randomBytes(16).toString("hex");
  sessions[token] = username;
  // 🐛 BUG #2 (CSRF enabler): session cookie without SameSite/HttpOnly/Secure
  res.setHeader("Set-Cookie", `sid=${token}; Path=/`);
  res.redirect("/board");
});

app.get("/logout", (req, res) => {
  const s = getSession(req);
  if (s) delete sessions[s.token];
  res.setHeader("Set-Cookie", "sid=; Path=/; Max-Age=0");
  res.redirect("/login");
});

function page(title, body, user) {
  return `<html><head><title>${title}</title></head><body>
    <nav>${user ? `Logged in as <b>${user}</b> | <a href="/transfer">Transfer</a> | <a href="/logout">Logout</a>` : `<a href="/login">Login</a>`}</nav>
    <hr>${body}</body></html>`;
}

// --- comment board (stored XSS) ---
app.get("/board", (req, res) => {
  const s = getSession(req);
  const user = s ? s.user : null;
  const list = comments
    .map((c) => `<div class="comment"><b>${c.author}</b>: ${c.body}</div>`) // 🐛 BUG #3 (stored XSS): comment body rendered raw
    .join("");
  res.send(
    page("Board", `
      <h1>Comment Board</h1>
      <form method="POST" action="/board/comment">
        <input name="author" placeholder="your name" value="${user || ""}">
        <textarea name="body" placeholder="comment"></textarea>
        <button>Post</button>
      </form>
      <div>${list}</div>
    `, user)
  );
});

app.post("/board/comment", (req, res) => {
  // 🐛 BUG #4 (CSRF): state-changing form with no CSRF token and no Origin/Referer check
  const { author, body } = req.body;
  comments.push({ id: comments.length + 1, author: author || "anon", body: String(body || "") });
  res.redirect("/board");
});

// --- search (reflected XSS) ---
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  const matches = comments.filter((c) => c.body.includes(q));
  const list = matches.map((c) => `<li>${c.author}: ${c.body}</li>`).join("");
  res.send(
    page("Search", `
      <h1>Search</h1>
      <form method="GET" action="/search">
        <input name="q" value="${q}"> <!-- 🐛 BUG #5 (reflected XSS): q reflected into attribute + DOM -->
        <button>Search</button>
      </form>
      <p>Results for: ${q}</p> <!-- 🐛 BUG #6 (reflected XSS): raw output -->
      <ul>${list}</ul>
      <script>document.getElementById('echo').textContent = 'You searched: ' + location.hash.slice(1);</script>
      <span id="echo"></span>
    `)
  );
});

// --- profile (DOM XSS) ---
app.get("/profile", (req, res) => {
  res.send(page("Profile", `
    <h1>Profile</h1>
    <div id="greeting"></div>
    <script>
      // 🐛 BUG #7 (DOM XSS): location data written via innerHTML
      const name = new URLSearchParams(location.search).get('name') || 'guest';
      document.getElementById('greeting').innerHTML = 'Hello, <b>' + name + '</b>!';
    </script>
  `));
});

// --- money transfer (classic CSRF target) ---
app.get("/transfer", (req, res) => {
  const s = getSession(req);
  if (!s) return res.redirect("/login");
  res.send(page("Transfer", `
    <h1>Transfer money</h1>
    <p>Balance: ${users[s.user].balance}</p>
    <form method="POST" action="/transfer">
      <input name="to" placeholder="recipient">
      <input name="amount" type="number" placeholder="amount">
      <button>Send</button>
    </form>
    <!-- no CSRF token 🐛 -->
  `, s.user));
});

app.post("/transfer", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).send("Not logged in");
  const { to, amount } = req.body;
  const amt = parseInt(amount, 10) || 0;
  // 🐛 BUG #8 (CSRF): no token, no Origin/Referer validation, cookie auth only
  users[s.user].balance -= amt;
  if (users[to]) users[to].balance += amt;
  res.send(page("Transfer", `<h1>Sent ${amt} to ${to}</h1><a href="/transfer">back</a>`, s.user));
});

// --- API used to demonstrate CORS bug ---
app.get("/api/me", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "unauthorized" });
  res.json({ user: s.user, balance: users[s.user].balance }); // sensitive data + CORS reflects origin
});

// --- delete comment (CSRF + IDOR-ish) ---
app.get("/board/delete", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).send("Not logged in");
  const id = parseInt(req.query.id, 10);
  // 🐛 BUG #9: GET request mutates state (CSRF-friendly), no ownership check
  const idx = comments.findIndex((c) => c.id === id);
  if (idx >= 0) comments.splice(idx, 1);
  res.redirect("/board");
});

app.listen(PORT, () => {
  console.log(`⚠️  Vulnerable lab running at http://localhost:${PORT}`);
  console.log("   Login with admin / admin123");
});
