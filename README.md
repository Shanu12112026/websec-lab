# websec-lab

⚠️ **INTENTIONALLY VULNERABLE — local security-training target only. Never deploy publicly or expose beyond localhost.**

A tiny Express app with planted web-security bugs to practice detection (e.g. with the `web-security` skill):

## Planted bugs

| # | Type | Where |
|---|------|-------|
| 1 | CORS reflects any `Origin` + credentials | `server.js` CORS middleware |
| 2 | Session cookie without `HttpOnly`/`Secure`/`SameSite` | `POST /login` |
| 3 | Stored XSS (comment body rendered raw) | `GET /board` |
| 4 | CSRF — no token on comment form | `POST /board/comment` |
| 5 | Reflected XSS into attribute | `GET /search?q=` |
| 6 | Reflected XSS into body | `GET /search?q=` |
| 7 | DOM XSS via `innerHTML` + `location` | `GET /profile?name=` |
| 8 | CSRF — transfer endpoint, no token/Origin check | `POST /transfer` |
| 9 | State-changing GET, no ownership check | `GET /board/delete?id=` |

## Run

```bash
npm install
npm start
# http://localhost:3000  — login: admin / admin123
```

## Practice ideas

- Reflected XSS: `http://localhost:3000/search?q=<img src=x onerror=alert(1)>`
- DOM XSS: `http://localhost:3000/profile?name=<img src=x onerror=alert(1)>`
- Stored XSS: post `<script>alert(1)</script>` as a comment on `/board`
- CSRF: host an HTML page that auto-submits a form to `POST /transfer`
- CORS: `curl -H "Origin: https://evil.example" http://localhost:3000/api/me -i`
