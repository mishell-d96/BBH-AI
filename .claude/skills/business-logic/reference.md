# Business Logic Vulnerabilities — Reference

Derived from PortSwigger Web Security Academy:
- https://portswigger.net/web-security/logic-flaws
- https://portswigger.net/web-security/logic-flaws/examples

## What they are

Business logic vulnerabilities (a.k.a. application logic vulnerabilities or logic
flaws) are flaws in the **design and implementation** of an application that
allow an attacker to **elicit unintended behavior**. They let an attacker
manipulate legitimate functionality to achieve a malicious goal, often by
circumventing rules intended to prevent illogical or negative outcomes.

They usually stay hidden during normal use because they only surface in scenarios
the developers never anticipated — an attacker interacting with the application in
ways its designers did not expect.

## How they arise

Logic flaws stem from **flawed assumptions** about how users interact with the
application and about the state of the system. Common root causes:

- **Inadequate input validation** — assuming all data arrives via a normal browser
  and relying on weak client-side controls, which a proxy trivially bypasses.
- **Complex systems** — architectures so complicated the team itself doesn't fully
  understand them, leaving room for flawed assumptions.
- **Siloed understanding** — different developers on a large codebase make wrong
  assumptions about components they don't own.
- **Poor / undocumented assumptions** — implicit assumptions that no one wrote down
  slip through review and testing.

## Impact

Impact varies entirely with the affected functionality:

- **Authentication / authorization logic** — privilege escalation or full auth
  bypass, exposing sensitive data and functions.
- **Financial / transactional logic** — direct monetary loss through fraud or theft.
- **Indirect damage** — even when the attacker gains nothing directly, they can
  disrupt or harm business operations.

In bug-bounty terms: payment, privilege, and cross-tenant data abuse are high
severity; trivial workflow quirks with no business/$ impact are noise.

## Categories with concrete examples

### 1. Excessive trust in client-side controls
Root assumption: users only ever interact through the provided web UI, so
client-side validation is "good enough". Attackers use tools like Burp Proxy to
modify data after the browser sends it but before the server processes it.
"Accepting data at face value, without performing proper integrity checks and
server-side validation, can allow an attacker to do all kinds of damage."
Example: a price, total, or quantity submitted in the request and trusted by the
server, edited in transit. Impact depends on how the server uses the value.

### 2. Failing to handle unconventional input
Applications should restrict input to values that comply with business rules, but
many fail to anticipate every scenario. A numeric field may accept values the
business logic should never permit — e.g. a numeric data type that accepts
**negative values**.
Example: a banking transfer with insufficient validation of a negative amount can
reverse the direction of the funds flow, so the attacker receives money instead
of sending it.
Test technique: submit extreme values, abnormally long strings, unexpected data
types (arrays, null), zero, and high-precision decimals to expose weak
validation.

### 3. Making flawed assumptions about user behavior
Several sub-patterns:

- **Trusted users stay trustworthy.** Controls enforced strictly at one point but
  relaxed later create loopholes "if business rules and security measures are not
  applied consistently throughout the application." Privileges granted under one
  condition may persist after that condition no longer holds.
- **Users always supply mandatory input.** Browsers stop ordinary users from
  submitting incomplete forms, but an attacker can tamper with or **remove**
  parameters entirely. Especially dangerous when multiple functions live in one
  server-side script and parameter presence selects the execution path.
- **Users follow the intended sequence.** Many workflows assume steps are completed
  in order. Attackers use **forced browsing** to replay requests out of order,
  potentially skipping security steps such as two-factor authentication if the
  server never verifies proper progression through the flow.

### 4. Domain-specific flaws
Contextual to the business domain; discounting in e-commerce is the classic
surface. Example: a shop gives 10% off orders over $1000. If the logic doesn't
re-verify the order composition after the discount is applied, an attacker can add
items to cross the $1000 threshold, earn the discount, then remove the unwanted
items while keeping the discount. Identifying these requires understanding the
domain's logic, how values are adjusted, and the attacker's likely objectives
(free goods, extra credit, stacked coupons, refund > paid, rounding abuse).

### 5. Providing an encryption oracle
Occurs when "user-controllable input is encrypted and the resulting ciphertext is
then made available to the user in some way." The attacker uses this as an oracle
to encrypt arbitrary data with the correct algorithm/key. The danger escalates
when another input expects identically-encrypted data: the attacker can generate
valid encrypted input for a sensitive function. If the application also exposes
decryption, the attacker gains further leverage for crafting exploits.

### 6. Email address parser discrepancies
Websites often parse an email address to extract the organizational domain for
access control (e.g. anyone at `@example.com` gets admin). Email parsing is
complex even for RFC-compliant addresses, and "discrepancies in how email
addresses are parsed can undermine this logic" when different parts of the
application parse the same address inconsistently. Attackers exploit this with
encoding tricks, comments, sub-addressing, or unicode — crafting an address that
passes registration validation but is interpreted by the access-control logic as
belonging to a privileged domain, granting access to admin panels or restricted
functions.

## Prevention

- Make sure developers and testers thoroughly understand the application's domain.
- Avoid implicit assumptions about user behavior and about other components.
- Verify server-side state assumptions are met before proceeding with each step.
- Maintain clear design documentation of all transactions, workflows, and
  assumptions.
- Write clear, comprehensible code so behavior doesn't depend on external docs.
- Document dependencies and consider the side-effects of manipulating each value.
- Conduct post-incident analysis to strengthen the development process.

## Testing checklist

1. Map the intended workflow end to end in a proxy; record every parameter,
   state transition, and server-side decision.
2. Write down each implicit assumption (sequence, presence, sign, source of
   truth, trust persistence).
3. Break each assumption individually: edit trusted values, remove params, reorder
   steps, send unconventional input, replay encrypted tokens cross-feature, abuse
   domain rules.
4. Confirm the server actually fails to re-validate, and measure concrete $ /
   privilege / data impact before reporting.
