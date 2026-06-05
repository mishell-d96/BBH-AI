# Recon-mapper report — demo.testfire.net

- Created: 2026-06-02T18:04:41Z  | Updated: 2026-06-02T18:15:45Z
- Scope: **1 in-scope** target(s), 0 excluded
  - In-scope rules: `*.demo.testfire.net, demo.testfire.net`
- Tools run: subfinder, dig, nmap, ffuf, nuclei
- Tools skipped: crt.sh (request failed or rate-limited); whois (error); waybackurls (not installed (gau also absent)); httpx (error); katana (not installed (gospider also absent))

## 1. Asset inventory
0 host(s) discovered (passive).

## 2. Attack-surface map
1 live host record(s), 21 endpoint(s), 0 JS file(s).

**Auth surface:** `web: POST /doLogin (uid/passw) -> session cookie`, `api: POST /api/login (JSON username/password) -> base64 Authorization token = base64(user:base64(pass):sig)`, `test creds: jsmith/demo1234 (AltoroMutual published demo creds); admin login hinted in HTML comment`, `jsmith owns: 800002 Savings, 800003 Checking, 4539082039396288 CreditCard`

**Manual supplement required (automated spidering is incomplete):**
- authenticated /bank/* web area (re-crawl per role with session)
- POST bodies for /api/transfer, /api/admin/* (baseline read-only)
- feedback.jsp stored-content rendering path

<details><summary>Full surface JSON</summary>

```json
{
  "note": "httpx failed in active_map.sh; surface rebuilt manually via curl crawl + swagger spec (/swagger/properties.json). nmap/ffuf/nuclei raw under raw/.",
  "hosts": [
    {
      "host": "demo.testfire.net",
      "ip": "65.61.137.117",
      "tech": [
        "Apache Tomcat/Coyote JSP engine",
        "AltoroJ (AltoroMutual demo bank)"
      ],
      "waf": "detected (nuclei waf-detect)",
      "ports": [
        {
          "port": 80,
          "state": "open",
          "service": "http"
        },
        {
          "port": 443,
          "state": "open",
          "service": "http/tls"
        },
        {
          "port": 8080,
          "state": "open",
          "service": "http"
        },
        {
          "port": 8443,
          "state": "closed"
        }
      ]
    }
  ],
  "endpoints": [
    {
      "url": "/doLogin",
      "methods": [
        "POST"
      ],
      "params": [
        "uid",
        "passw",
        "btnSubmit"
      ],
      "auth": "none",
      "source": "login.jsp form",
      "note": "web login -> sets session cookie, 302"
    },
    {
      "url": "/login.jsp",
      "methods": [
        "GET"
      ],
      "params": [],
      "auth": "none",
      "source": "crawl",
      "note": "HTML comment leaks SiteOps phone for admin login"
    },
    {
      "url": "/index.jsp",
      "methods": [
        "GET"
      ],
      "params": [
        "content"
      ],
      "auth": "none",
      "source": "crawl",
      "note": "content= loads .htm templates -> path-traversal/LFI candidate"
    },
    {
      "url": "/search.jsp",
      "methods": [
        "GET"
      ],
      "params": [
        "query"
      ],
      "auth": "none",
      "source": "form",
      "note": "reflected XSS candidate"
    },
    {
      "url": "/feedback.jsp",
      "methods": [
        "GET",
        "POST"
      ],
      "params": [
        "name",
        "email_addr",
        "subject",
        "comments"
      ],
      "auth": "none",
      "source": "crawl",
      "note": "stored XSS / SQLi candidate"
    },
    {
      "url": "/status_check.jsp",
      "methods": [
        "GET"
      ],
      "params": [],
      "auth": "none",
      "source": "crawl"
    },
    {
      "url": "/subscribe.jsp",
      "methods": [
        "GET",
        "POST"
      ],
      "params": [
        "txtEmail"
      ],
      "auth": "none",
      "source": "crawl"
    },
    {
      "url": "/survey_questions.jsp",
      "methods": [
        "GET"
      ],
      "params": [],
      "auth": "none",
      "source": "crawl"
    },
    {
      "url": "/admin",
      "methods": [
        "GET"
      ],
      "params": [],
      "auth": "redirect",
      "source": "ffuf",
      "note": "302"
    },
    {
      "url": "/bank/",
      "methods": [
        "GET"
      ],
      "params": [],
      "auth": "session",
      "source": "ffuf",
      "note": "302 -> login.jsp; authenticated banking area"
    },
    {
      "url": "/api/login",
      "methods": [
        "GET",
        "POST"
      ],
      "params": [
        "username",
        "password"
      ],
      "auth": "none",
      "source": "swagger",
      "note": "POST returns base64 token jsmith:base64(pw):sig; SQLi candidate"
    },
    {
      "url": "/api/account",
      "methods": [
        "GET"
      ],
      "params": [],
      "auth": "bearer",
      "source": "swagger",
      "note": "lists caller's accounts"
    },
    {
      "url": "/api/account/{accountNo}",
      "methods": [
        "GET"
      ],
      "params": [
        "accountNo"
      ],
      "auth": "bearer",
      "source": "swagger",
      "note": "TOP CANDIDATE: BOLA/IDOR; account IDs sequential (800002,800003)"
    },
    {
      "url": "/api/account/{accountNo}/transactions",
      "methods": [
        "GET",
        "POST"
      ],
      "params": [
        "accountNo"
      ],
      "auth": "bearer",
      "source": "swagger",
      "note": "BOLA on transaction history"
    },
    {
      "url": "/api/transfer",
      "methods": [
        "POST"
      ],
      "params": [],
      "auth": "bearer",
      "source": "swagger",
      "note": "money movement; logic/IDOR candidate"
    },
    {
      "url": "/api/feedback/submit",
      "methods": [
        "POST"
      ],
      "params": [],
      "auth": "unknown",
      "source": "swagger"
    },
    {
      "url": "/api/feedback/{feedbackId}",
      "methods": [
        "GET"
      ],
      "params": [
        "feedbackId"
      ],
      "auth": "unknown",
      "source": "swagger",
      "note": "BOLA on feedback messages"
    },
    {
      "url": "/api/admin/addUser",
      "methods": [
        "POST"
      ],
      "params": [],
      "auth": "unknown",
      "source": "swagger",
      "note": "VERTICAL PRIV-ESC candidate: admin fn reachable by low-priv?"
    },
    {
      "url": "/api/admin/changePassword",
      "methods": [
        "POST"
      ],
      "params": [],
      "auth": "unknown",
      "source": "swagger",
      "note": "VERTICAL PRIV-ESC / ATO candidate"
    },
    {
      "url": "/api/logout",
      "methods": [
        "GET"
      ],
      "params": [],
      "auth": "bearer",
      "source": "swagger"
    },
    {
      "url": "/swagger/index.html",
      "methods": [
        "GET"
      ],
      "params": [],
      "auth": "none",
      "source": "nuclei",
      "note": "Swagger UI; spec at /swagger/properties.json (publicly readable)"
    }
  ],
  "js_files": [],
  "secrets_leads": [
    "login.jsp HTML comment: 'To get the latest admin login, please contact SiteOps at 415-555-6159'",
    "/swagger/properties.json publicly readable -> full API contract incl. admin endpoints"
  ],
  "auth_surface": [
    "web: POST /doLogin (uid/passw) -> session cookie",
    "api: POST /api/login (JSON username/password) -> base64 Authorization token = base64(user:base64(pass):sig)",
    "test creds: jsmith/demo1234 (AltoroMutual published demo creds); admin login hinted in HTML comment",
    "jsmith owns: 800002 Savings, 800003 Checking, 4539082039396288 CreditCard"
  ],
  "manual_supplement_required": [
    "authenticated /bank/* web area (re-crawl per role with session)",
    "POST bodies for /api/transfer, /api/admin/* (baseline read-only)",
    "feedback.jsp stored-content rendering path"
  ]
}
```

</details>

## 3. Verified happy flows (baselines)

### api-login
- Success signal: 200 + Authorization token
- Baseline request:
```
POST /api/login  Content-Type: application/json  {"username":"jsmith","password":"demo1234"}
```
- Baseline response:
```
200 {"Authorization":"YW5OdGFYUm86WkdWdGJ6RXlNelE9Oj8WZn8rPw==","success":"jsmith is now logged in"}
```

### api-account-list
- Success signal: 200 + caller's own account list
- Baseline request:
```
GET /api/account  Authorization: <token>
```
- Baseline response:
```
200 {"Accounts":[{"Name":"Savings","id":"800002"},{"Name":"Checking","id":"800003"},{"Name":"Credit Card","id":"4539082039396288"}]}
```

### api-account-detail-baseline
- Success signal: 200 + full balance/credit/debit/transaction detail
- Baseline request:
```
GET /api/account/800003  Authorization: <jsmith token>
```
- Baseline response:
```
200 {accountId:800003, balance, credits[], debits[], last_10_transactions[]}
```

## 4. Impact-scored vulnerability candidates

| # | Priority | Endpoint | Suspected class | Baseline | Evidence |
|---|----------|----------|-----------------|----------|----------|
| C1 | 100 (L5×I5×E4) | `GET https://demo.testfire.net/api/account/{accountNo}` | access-control / IDOR / BOLA | api-account-detail-baseline | Authenticated read of full balance + credits/debits + transactions; account IDs sequential (jsmith=800002,800003). No object-ownership check apparent in spec. |
| C2 | 80 (L5×I4×E4) | `GET https://demo.testfire.net/api/account/{accountNo}/transactions` | access-control / IDOR / BOLA | api-account-detail-baseline | Same sequential-id endpoint exposes per-account transaction history. |
| C5 | 80 (L4×I5×E4) | `POST https://demo.testfire.net/api/login` | sql-injection / auth bypass | api-login | Classic AltoroMutual login; username reflected into token. SQLi auth-bypass historically present. |
| C6 | 64 (L4×I4×E4) | `GET https://demo.testfire.net/index.jsp?content=` | path-traversal / LFI | None | content= loads .htm templates from disk; classic path-traversal/LFI shape. |
| C3 | 60 (L4×I5×E3) | `POST https://demo.testfire.net/api/admin/addUser` | access-control / vertical privilege escalation | api-login | Admin endpoint published in public swagger; reachability by a low-priv (jsmith) token unverified. |
| C4 | 60 (L4×I5×E3) | `POST https://demo.testfire.net/api/admin/changePassword` | access-control / ATO | api-login | Admin password-change endpoint in public swagger; authz unverified. |
| C8 | 32 (L4×I2×E4) | `GET https://demo.testfire.net/search.jsp?query=` | xss (reflected) | None | query reflected; reflected XSS candidate. |
| C7 | 27 (L3×I3×E3) | `GET https://demo.testfire.net/api/feedback/{feedbackId}` | access-control / IDOR | None | Numeric feedbackId object reference; cross-user message read candidate. |
| C9 | 27 (L3×I3×E3) | `POST https://demo.testfire.net/feedback.jsp` | xss (stored) / sql-injection | None | comments field stored + rendered; stored XSS / SQLi candidate. |

## 5. Skill-routing table
9 candidate(s) routed, **0 gap(s)**.

| # | Endpoint | Hypothesis | → Skill | Confidence | Chain next |
|---|----------|-----------|---------|-----------|-----------|
| C1 | `GET https://demo.testfire.net/api/account/{accountNo}` | Authenticated read of full balance + credits/debits + transactions; account IDs sequential (jsmith=800002,800003). No object-ownership check apparent in spec. | /access-control-idor | 14 | authentication, reporting |
| C2 | `GET https://demo.testfire.net/api/account/{accountNo}/transactions` | Same sequential-id endpoint exposes per-account transaction history. | /access-control-idor | 14 | authentication, reporting |
| C5 | `POST https://demo.testfire.net/api/login` | Classic AltoroMutual login; username reflected into token. SQLi auth-bypass historically present. | /sql-injection | 13 | authentication |
| C6 | `GET https://demo.testfire.net/index.jsp?content=` | content= loads .htm templates from disk; classic path-traversal/LFI shape. | /path-traversal | 10 | — |
| C3 | `POST https://demo.testfire.net/api/admin/addUser` | Admin endpoint published in public swagger; reachability by a low-priv (jsmith) token unverified. | /access-control-idor | 12 | authentication, reporting |
| C4 | `POST https://demo.testfire.net/api/admin/changePassword` | Admin password-change endpoint in public swagger; authz unverified. | /access-control-idor | 9 | authentication, reporting |
| C8 | `GET https://demo.testfire.net/search.jsp?query=` | query reflected; reflected XSS candidate. | /xss | 8 | csrf, access-control-idor |
| C7 | `GET https://demo.testfire.net/api/feedback/{feedbackId}` | Numeric feedbackId object reference; cross-user message read candidate. | /access-control-idor | 14 | authentication, reporting |
| C9 | `POST https://demo.testfire.net/feedback.jsp` | comments field stored + rendered; stored XSS / SQLi candidate. | /sql-injection | 10 | authentication |

