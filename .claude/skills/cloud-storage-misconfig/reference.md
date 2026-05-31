# Cloud Storage Misconfiguration — Deep Reference

Object storage (S3, GCS, Azure Blob) is misconfigured when access controls let
unauthorized/anonymous principals **list, read, write, or delete** objects, or
when a referenced bucket name is **unclaimed** (takeover). This reference covers
discovery, per-provider anonymous testing, the permission model, takeover,
chaining, ethical proof, and prevention.

Always operate from the `/recon-mapper` asset inventory. Public ≠ vulnerable —
impact is driven by what the bucket *contains and serves*.

---

## 1. Bucket discovery

Sources, in rough order of signal:

- **URLs / asset hosts** — anything resolving to:
  - S3: `https://<bucket>.s3.amazonaws.com`, `https://<bucket>.s3.<region>.amazonaws.com`, `https://s3.<region>.amazonaws.com/<bucket>`
  - GCS: `https://storage.googleapis.com/<bucket>/<object>`, `https://<bucket>.storage.googleapis.com`
  - Azure: `https://<account>.blob.core.windows.net/<container>/<blob>`
- **JS / HTML / sourcemaps** — grep bundles and `*.map` for the host patterns and bare bucket names; SDK config blocks often hardcode bucket + region.
- **DNS / CNAME** — subdomains CNAME'd to a storage endpoint. A CNAME to a storage host that returns `NoSuchBucket`/`404` is a takeover candidate.
- **Certificate Transparency (CT) logs** — crt.sh for subdomains hinting at bucket naming.
- **Reverse IP / dorking** — `site:s3.amazonaws.com <org>`, Bing reverse-IP, GitHub code search for the org's bucket strings.
- **Naming brute force** — orgs reuse patterns: `<org>`, `<org>-prod`, `-dev`, `-staging`, `-backup`, `-backups`, `-assets`, `-static`, `-uploads`, `-media`, `-logs`, `-data`, `-internal`, `-cdn`. Bucket namespaces are global per provider, so guessable names are findable.

Tools:
- `cloud_enum` — multi-cloud (S3/GCS/Azure) name brute + access check.
- `S3Scanner` — S3 discovery + permission dump.
- `GCPBucketBrute` — GCS name brute + IAM/anonymous check.
- `MicroBurst` (`Invoke-EnumerateAzureBlobs -Base <account>`) — Azure container wordlist enum.

---

## 2. Per-provider anonymous test commands

All probes below are **unauthenticated** — no keys, no signing. They confirm
*anonymous* access specifically (the high-signal finding).

### AWS S3 (`--no-sign-request`)
```bash
# LIST objects
aws s3 ls s3://BUCKET --no-sign-request
curl -s https://BUCKET.s3.amazonaws.com/               # 200 = public listing XML

# READ a single object
aws s3 cp s3://BUCKET/KEY - --no-sign-request | head    # stream, don't bulk pull
curl -s https://BUCKET.s3.amazonaws.com/KEY

# READ_ACP — who can do what
aws s3api get-bucket-acl --bucket BUCKET --no-sign-request
aws s3api get-object-acl --bucket BUCKET --key KEY --no-sign-request

# WRITE (only to place a single harmless marker — see §6)
aws s3 cp poc.txt s3://BUCKET/bbp-poc-marker.txt --no-sign-request

# WRITE_ACP (do NOT actually change ACLs in a real target — probe-only awareness)
# aws s3api put-bucket-acl --bucket BUCKET --acl public-read --no-sign-request
```
Response triage: a directory-listing XML or object bytes = vulnerable read;
`AccessDenied` = locked (or object-level only); `NoSuchBucket` = takeover lead.

### Google Cloud Storage
```bash
# LIST (XML/JSON API, anonymous)
gsutil ls gs://BUCKET
curl -s "https://storage.googleapis.com/storage/v1/b/BUCKET/o"   # JSON object list
curl -s "https://storage.googleapis.com/BUCKET/"                  # XML list

# READ a single object
curl -s "https://storage.googleapis.com/BUCKET/OBJECT" | head

# WRITE marker (if allUsers has objects.create)
gsutil cp poc.txt gs://BUCKET/bbp-poc-marker.txt
```
Public read = `allUsers` granted `storage.objects.get`; public list =
`allUsers` granted `storage.objects.list`. 200 without auth confirms it.

### Azure Blob Storage
```bash
# Container-level public access → anonymous directory listing
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"

# Blob-level public access → direct fetch by full URL (no listing)
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER/BLOB"

# Anonymous CLI listing
az storage blob list --account-name ACCOUNT --container-name CONTAINER --auth-mode login --only-show-errors  # or anonymous public access
```
Three access levels: **Private** (none), **Blob** (read a blob only if you know
its URL), **Container** (anonymous listing — most dangerous). Also watch for
over-scoped / long-lived **SAS tokens** in URLs.

---

## 3. Permission classes (S3 ACL model)

| Class | Grants |
|---|---|
| **READ** | List bucket objects / read object contents |
| **WRITE** | Create, overwrite, and **delete** objects |
| **READ_ACP** | Read the bucket/object ACL |
| **WRITE_ACP** | Modify the ACL (can self-escalate to FULL_CONTROL) |
| **FULL_CONTROL** | READ + WRITE + READ_ACP + WRITE_ACP |

Granted to special groups: `AllUsers` (anyone on the internet, incl. anonymous)
or `AuthenticatedUsers` (any AWS account — still effectively everyone). The
classic root cause is a wildcard policy `"Action": "*"` / `"Principal": "*"`, or
disabled S3 Block Public Access. **WRITE** is the dangerous one for tampering;
**WRITE_ACP** lets an attacker rewrite the ACL and take full control even if
WRITE wasn't directly granted. GCS/Azure map to the same conceptual read / list
/ write / acl-control split via IAM roles and container access levels.

---

## 4. Dangling-bucket takeover

When a bucket is deleted but a DNS record (CNAME) or hardcoded reference still
points at it, the global name becomes re-claimable.

Steps:
1. Find a subdomain/host CNAME'd to a storage endpoint that returns
   `NoSuchBucket` (S3) / `404` / `NoSuchKey` with no bucket.
2. Confirm the name is unclaimed (`aws s3 ls s3://NAME --no-sign-request` →
   `NoSuchBucket`).
3. Create a bucket with the **exact** name in your own account, in the region
   the CNAME expects, and enable static website hosting if the reference uses
   the website endpoint.
4. Place a **single benign marker** proving the victim host now serves your
   content. Do not host real payloads.
5. Document (DNS record, NoSuchBucket proof, claim proof), report, then **delete
   your bucket / release the name**.

Impact: any subdomain CNAME'd to it is taken over — serve arbitrary JS/HTML from
a first-party-looking, trusted origin (cookies, CSP trust, brand abuse).

Reference matrix: `can-i-take-over-xyz` (EdOverflow) for which services are
takeover-able and the exact fingerprints.

---

## 5. Chaining for impact

- **Writable bucket serving JS/HTML** → overwrite served code → **stored XSS /
  supply-chain** across every page that loads it. Hand to `/xss`.
- **Readable bucket with secrets** — `.env`, `config.*`, `*.pem`, `id_rsa`,
  backups, DB dumps, `.git`, terraform state, CI artifacts → `/secrets-exposure`
  for credential validation and blast-radius.
- **Bucket takeover** → trusted-asset poisoning; combine with any page that
  loads the host as a script/style source for guaranteed execution.
- **Public list of "internal" buckets** → recon goldmine (filenames leak
  product names, customers, infra) even when individual objects are restricted.

---

## 6. Ethical proof (mandatory)

This is an authorized, scope-gated workspace. Prove access **minimally**:

- **Read** — list, and fetch *one* representative object to show sensitivity.
  Never bulk-download. Redact object names/contents in evidence.
- **Write** — write exactly **one** harmless marker, then delete it:
  ```bash
  echo "bbp-poc-$(date +%s) authorized test" > poc.txt
  aws s3 cp poc.txt s3://BUCKET/bbp-poc-marker.txt --no-sign-request   # 1) write
  curl -s https://BUCKET.s3.amazonaws.com/bbp-poc-marker.txt           # 2) confirm
  aws s3 rm s3://BUCKET/bbp-poc-marker.txt --no-sign-request           # 3) cleanup
  ```
- **ACL** — read ACLs to demonstrate; do **not** actually modify a target's ACL.
- **Takeover** — claim, prove, release.

Never: overwrite or delete existing objects, read other users' data in bulk,
exfiltrate PII, leave persistent artifacts, or deploy live exploit payloads.
Log to `./_EXPLOIT/` only after the access is *proven*: exact command(s),
redacted evidence, timestamp, and confirmation that any marker was removed.

---

## 7. Prevention (for the report's remediation section)

- **S3** — enable account- and bucket-level **Block Public Access**; remove
  `AllUsers`/`AuthenticatedUsers` grants; never use `"Principal": "*"` /
  `"Action": "*"`; scope IAM to least privilege; enable bucket logging.
- **GCS** — enable **Public Access Prevention** and **Uniform bucket-level
  access**; remove `allUsers`/`allAuthenticatedUsers` IAM bindings.
- **Azure** — set containers to **Private**; disable "Allow Blob anonymous
  access" at the storage-account level; use short-lived, least-privilege SAS.
- **Dangling references** — remove DNS records when decommissioning storage;
  monitor CNAMEs for `NoSuchBucket`/`404`; retain bucket names you still
  reference.

---

## Sources
- YesWeHack — Abusing S3 Bucket Permissions: https://www.yeswehack.com/learn-bug-bounty/abusing-s3-bucket-permissions
- Hacking The Cloud — Anonymous Blob Access (Azure): https://hackingthe.cloud/azure/anonymous-blob-access/
- can-i-take-over-xyz (S3 takeover fingerprints): https://github.com/EdOverflow/can-i-take-over-xyz
- Google Cloud Storage request endpoints: https://cloud.google.com/storage/docs/request-endpoints
- Everything About Cloud Bucket Hacking (S3/GCS/Azure/Firebase): https://medium.com/@anas-nady/everything-about-cloud-bucket-hacking-s3-gcs-azure-firebase-c027e9441ff9
