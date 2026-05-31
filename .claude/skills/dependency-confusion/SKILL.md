---
name: dependency-confusion
description: >-
  Find and prove dependency confusion / supply-chain exposure where an internal
  package name is unclaimed on a public registry, so a build that searches both
  private and public sources can be tricked into fetching attacker code. Use when
  package.json / requirements.txt / pom.xml / Gemfile / build.gradle / nuget.config
  is leaked in client JS, source maps, repos, CI logs, or error messages; when
  internal or scoped package names (npm @scope, PyPI, Maven groupId/artifactId,
  RubyGems, NuGet) are not present on the public registry; when references to a
  private/internal registry, Artifactory, Azure Artifacts, or --extra-index-url
  appear. Keywords: dependency confusion, namespace squatting, supply chain,
  unclaimed package, internal package, private registry, npm scope, .npmrc.
---

# Dependency Confusion

> **Prereq — map first:** Don't test this cold. A target attack-surface map must exist first — run `/recon-mapper` if not. Harvest internal package names from the JS/repos/manifests it surfaces. ALSO confirm the program permits this technique before publishing anything. Chain to proven RCE-in-build over a bare claim.

Internal package name referenced by the target + that name unclaimed on the public
registry = a build resolving both private and public sources can be steered to your
package. Proving it means real code execution inside the target's build/CI.

## When to test
Test when you have surfaced an **internal package name tied to the target**:
- `package.json` / `requirements.txt` / `pom.xml` / `build.gradle` / `Gemfile` / `*.csproj` / `nuget.config` leaked in repos, CI logs, Docker layers, or backups.
- Internal dependency names embedded in client JS bundles or source maps (webpack output, `//# sourceMappingURL`).
- Stack traces / verbose error pages that print `require('@acme/...')` or import paths.
- References to a private registry (Artifactory, Azure Artifacts, GitHub Packages) or `--extra-index-url`, scope-to-registry lines in `.npmrc`.
- Accidentally-public internal packages (org member published once, then privatized name).

## Impact & priority (HONEST)
- A **confirmed callback from the target's build/CI** = arbitrary code execution in their pipeline = **critical, RCE-class** (lateral movement, secret theft, artifact poisoning).
- BUT this is an **active, outward supply-chain technique**: you publish to a public registry that anyone may install. It is not passive.
- Therefore: **verify program permission first** (many VDPs/programs explicitly prohibit publishing to public registries) and prove only with a **benign out-of-band callback**. No callback = no proof = not a finding.
- A merely-unclaimed name with no demonstrated install is **low/informational**, not critical.

## Detection
1. Extract every internal / scoped package name from the manifests, JS, or errors found in recon.
2. For each, query the relevant **public** registry to see if the name is claimed:
   - npm: `npm view <name>` / registry.npmjs.org/<name>
   - PyPI: pypi.org/pypi/<name>/json
   - Maven: search.maven.org for groupId:artifactId
   - RubyGems: rubygems.org/api/v1/gems/<name>.json
   - NuGet: api.nuget.org/v3-flatcontainer/<name>/index.json
3. **Unclaimed public name that is referenced internally = a candidate.** Note version pinning — you must out-rank the private version.
4. Confirm the name is genuinely internal (org prefix, not a typo of a real public package, not a private scope already locked to a registry).

## Exploitation
Publish a **benign placeholder** under the unclaimed name with a **higher version** than the internal one (precedence: most resolvers pick the highest version across sources):
- Add a lifecycle hook that fires on install/build — npm `preinstall`, PyPI `setup.py`/sdist build step, Maven plugin goal, RubyGems extension, NuGet install script.
- The hook performs a **harmless OOB callback only**: a DNS or HTTP request to your own collaborator carrying **hostname / whoami** so you can attribute the source. Nothing else.
- Wait for a callback from **target infrastructure** (corporate egress IP, internal hostname pattern). That callback is the proof.
- Keep the package live only as long as needed; **unpublish/yank immediately** after capturing proof.

## Safety & ethics
- **Benign payload only.** Hostname + username via DNS/HTTP to your collaborator. No file reads, no env/secret exfil, no network scanning, no persistence, no destruction.
- **Honor program rules** — if the program prohibits publishing to public registries, do NOT publish; report the unclaimed-name exposure as a lower-severity gap instead.
- Minimize blast radius: highest version only as needed, narrow callback, prompt unpublish.
- Log nothing sensitive that the callback happens to surface; redact in the report.

## Minimal PoC (for ./_EXPLOIT/)
Record: the **unclaimed internal package name**, the registry, the internal version you out-ranked, your published version, the benign hook source, the **collaborator log line(s)** showing a callback from target infra (timestamp + source IP/hostname), and confirmation you unpublished. That callback is the load-bearing evidence.

## Don't report as noise
- Internal name that **is** claimed, or a scoped name already locked to a private registry (`@scope:registry=` in `.npmrc`).
- A public-registry name with **no demonstrated link to the target**.
- An unclaimed name with **no callback** — speculation, not proof.
- A typosquat of a real public package (different vuln class).

## Deep reference
See `reference.md` for per-ecosystem resolution/version precedence, name-harvesting techniques, the benign-callback proof setup, OOB infrastructure, ethics/unpublishing, and prevention.
- https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- https://github.blog/security/supply-chain-security/avoiding-npm-substitution-attacks/
