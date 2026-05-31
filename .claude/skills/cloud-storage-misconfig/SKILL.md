---
name: cloud-storage-misconfig
description: >-
  Find and prove misconfigured cloud storage — public or world-writable S3,
  GCS, and Azure Blob buckets, plus dangling/unclaimed bucket references.
  Use when you see s3.amazonaws.com / storage.googleapis.com /
  blob.core.windows.net URLs, bucket names embedded in JS or HTML, asset/CDN
  hosts, AccessDenied / NoSuchBucket / 404 responses, or upload features backed
  by object storage. Covers anonymous list/read/write, ACL probing, and bucket
  takeover.
---

# Cloud Storage Misconfiguration

> **Prereq — surfaced during mapping:** This class is driven by `/recon-mapper`'s asset inventory (Phase 1/2 hosts, JS, asset URLs). Run the map first and test the buckets/storage hosts it discovers. Prioritize by what the bucket contains/serves and chain into data exposure, asset tampering, or takeover.

## When to test
- Asset/CDN URLs resolving to `*.s3.amazonaws.com`, `s3.<region>.amazonaws.com/<bucket>`, `storage.googleapis.com/<bucket>`, or `<account>.blob.core.windows.net`.
- Bucket names hardcoded in JS bundles, HTML `src`/`href`, sourcemaps, mobile app strings, or DNS CNAMEs.
- Upload/avatar/import features that store user content (likely backed by a bucket).
- `AccessDenied`, `NoSuchBucket`, or a `404` on a subdomain CNAME'd to a storage host (takeover signal).

## Impact & priority (be honest)
- **High** — anonymous READ of *sensitive* objects (PII, creds, backups, internal docs); anonymous WRITE (overwrite served JS/assets → stored XSS / supply-chain); **bucket takeover** of a referenced-but-unclaimed name (full control of a trusted host/subdomain).
- **Medium** — writable bucket with no served/executed content, or readable non-public objects of limited sensitivity.
- **Low / noise** — a public bucket that only serves already-public assets (logos, marketing images), no write, no sensitive data, no dangling reference.

Prioritize by *what the bucket holds and serves*, not by "it's public." Public ≠ vulnerable.

## Detection
1. **Resolve bucket names** from the recon-mapper inventory: URLs, JS/sourcemaps, DNS, CT logs; brute likely names (`<org>-prod`, `-dev`, `-backup`, `-assets`, `-uploads`) with `cloud_enum` / `S3Scanner` / `GCPBucketBrute`.
2. **S3** — anonymous probe (no creds):
   - `aws s3 ls s3://BUCKET --no-sign-request` (list)
   - `aws s3api get-bucket-acl --bucket BUCKET --no-sign-request` (READ_ACP)
   - `curl -s -o /dev/null -w '%{http_code}' https://BUCKET.s3.amazonaws.com/` (200 listing vs AccessDenied vs NoSuchBucket).
3. **GCS** — `gsutil ls gs://BUCKET` or `curl -s "https://storage.googleapis.com/storage/v1/b/BUCKET/o"` (anonymous object list; 200 = public list).
4. **Azure Blob** — `curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"` (XML listing = Container-level public access).
5. **Takeover** — if a host/subdomain CNAMEs to a storage endpoint and returns `NoSuchBucket`/`404`, the name is unclaimed.

## Exploitation
- **Read** — list one object index, fetch a single sensitive object to confirm exposure (do not bulk-download).
- **Write** — if write is permitted, upload one harmless marker (see Minimal PoC), confirm it lands, then delete it. Never overwrite or delete existing objects.
- **Takeover** — claim the unclaimed bucket name in your own account, place a single benign marker proving you now serve the referenced host, document, then release.
- **Write → XSS** — if the bucket serves executable JS/HTML to the app origin, a writable bucket means you can poison served code (supply-chain). Prove with an inert marker, not a live payload.

## Chain for impact
- Writable JS/served asset → `/xss` (stored) and supply-chain compromise of every page loading it.
- Creds / config / `.env` / keys found in a readable bucket → `/secrets-exposure`.
- Bucket takeover of a trusted asset host → trusted-asset poisoning, malware/JS delivery from a first-party-looking origin.

## Minimal PoC (for ./_EXPLOIT/)
Log the exact command + redacted evidence. Examples:
- Read: `aws s3 ls s3://BUCKET --no-sign-request` → first lines of listing (redact object names if sensitive).
- Write proof (cleanup mandatory):
  ```
  echo "bbp-poc-$(date +%s)" > poc.txt
  aws s3 cp poc.txt s3://BUCKET/bbp-poc-marker.txt --no-sign-request   # write
  curl -s https://BUCKET.s3.amazonaws.com/bbp-poc-marker.txt           # confirm
  aws s3 rm s3://BUCKET/bbp-poc-marker.txt --no-sign-request           # cleanup
  ```
- Takeover: screenshot of `NoSuchBucket` on the referenced host + proof you claimed the name (benign marker served), then release.

Evidence: one marker, redacted listings, command transcript, timestamp. No bulk reads, no destruction, no real payloads.

## Don't report as noise
- Intentionally public asset/CDN buckets serving only already-public content, with no write and no sensitive objects.
- A readable bucket where every object is also reachable from the public site anyway.
- "Public" status alone with no demonstrated read of sensitive data, no write, and no dangling reference.

## Deep reference
See `reference.md` for discovery sources, per-provider anonymous test commands, the full permission-class matrix, dangling-bucket takeover steps, chaining, ethical proof, and prevention. Sources: YesWeHack S3 permissions guide, Hacking The Cloud (Azure anonymous blob), can-i-take-over-xyz (S3 takeover).
