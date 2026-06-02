export const meta = {
  name: 'panel',
  description: 'Two-agent adversarial panel that pressure-tests a candidate finding before reporting',
  phases: [
    { title: 'Advocate', detail: 'Strongest concrete case for the finding' },
    { title: 'Verdict', detail: 'Skeptic refutes, then returns the go/no-go' },
  ],
}

// ---- Inputs (override via the Workflow `args` value) -------------------------
// args may be:
//   - a string                       -> the topic/finding to judge
//   - { topic, evidence, rebuttals }  -> rebuttals = extra advocate<->skeptic
//                                         exchanges before the verdict (default 0)
// IMPORTANT: workflow scripts cannot read files. Paste the actual evidence
// (request/response, executed PoC + its REAL output, affected in-scope URL,
// relevant _RECON excerpts) into `cfg.evidence` — the panel judges real material,
// it cannot run anything itself.
const cfg = (typeof args === 'string') ? { topic: args } : (args ?? {})

const TOPIC = cfg.topic
  ?? 'Is the candidate finding a real, reportable, high-impact vulnerability? Prove it or discard it.'
const EVIDENCE = cfg.evidence
  ?? '(none supplied — treat the absence of concrete evidence as a blocker, not an assumption.)'
const REBUTTALS = cfg.rebuttals ?? 0   // extra exchanges before verdict; 0 = lean 2-agent panel

const RULES = [
  'Workspace rules in force:',
  '- SCOPE GATE: only in-scope assets; flag any out-of-scope assumption.',
  '- Impact-first: a concrete, provable impact hypothesis is required.',
  '- No speculation: ban "might/could/may be exploitable" — proved or not.',
  '- Minimal, safe PoC required; no destructive/bulk actions.',
  '- Signal over noise: headers/CSP/self-XSS/version-disclosure are not standalone findings.',
  '',
  'WHAT THIS PANEL CAN AND CANNOT DO: no agent here can run curl, hit the target,',
  'or execute a PoC. Judge ONLY the argument and the EVIDENCE supplied. Treat any',
  'claim whose proof is not present in the EVIDENCE as UNPROVEN. "Reportable" means',
  'the case clears the bar GIVEN that the cited PoC was actually executed and its',
  'real output appears in the EVIDENCE — never assume it was.',
].join('\n')

const HEADER = `TOPIC:\n${TOPIC}\n\n${RULES}\n\n`
  + `=== EVIDENCE (the only concrete material; do not invent beyond it) ===\n${EVIDENCE}\n`

// ---- Agent 1: ADVOCATE — strongest concrete case ----------------------------
phase('Advocate')
let transcript = HEADER
const advocacy = await agent(
  `You are the ADVOCATE. Make the strongest concrete case that this is a real, high-impact, `
  + `reportable vulnerability: the exact attack path, the affected in-scope asset, the minimal PoC, `
  + `and the business impact ("if X then attacker does Y to asset Z causing W"). Cite only what the `
  + `EVIDENCE actually proves — no speculation, no hand-waving.\n\n${transcript}`,
  { label: 'advocate', phase: 'Advocate' },
)
if (advocacy) transcript += `\n[ADVOCATE]:\n${advocacy}\n`

// ---- Optional extra exchanges (only if the operator asked for more rigor) ----
for (let r = 0; r < REBUTTALS; r++) {
  const sk = await agent(
    `You are the SKEPTIC. Adversarially refute the ADVOCATE: missing preconditions, out-of-scope `
    + `assumptions, unproven steps, hedging, duplicates/accepted-risk, or noise. Add only your next turn.\n\n${transcript}`,
    { label: `skeptic rebuttal ${r + 1}`, phase: 'Advocate' },
  )
  if (sk) transcript += `\n[SKEPTIC]:\n${sk}\n`
  const adv = await agent(
    `You are the ADVOCATE. Answer the SKEPTIC's objections with proof from the EVIDENCE, or concede `
    + `the point. Add only your next turn.\n\n${transcript}`,
    { label: `advocate rebuttal ${r + 1}`, phase: 'Advocate' },
  )
  if (adv) transcript += `\n[ADVOCATE]:\n${adv}\n`
}

// ---- Agent 2: SKEPTIC — refute, then deliver the verdict ---------------------
phase('Verdict')
const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['verdict', 'severity', 'rationale', 'missing_to_prove', 'next_steps'],
  properties: {
    verdict: {
      type: 'string',
      enum: ['REPORTABLE', 'NEEDS_MORE_PROOF', 'DISCARD'],
      description: 'Final call against the prove-it-or-discard-it bar.',
    },
    severity: {
      type: 'string',
      enum: ['critical', 'high', 'medium', 'low', 'none'],
      description: 'Honest severity if reportable; otherwise none.',
    },
    rationale: { type: 'string', description: 'Why this verdict, citing the strongest points for and against.' },
    missing_to_prove: {
      type: 'array', items: { type: 'string' },
      description: 'Concrete gaps still blocking a report (empty if REPORTABLE).',
    },
    next_steps: {
      type: 'array', items: { type: 'string' },
      description: 'Exact next actions — which vuln-class skill to run, what PoC to capture.',
    },
  },
}

const verdict = await agent(
  `You are the SKEPTIC and final arbiter — neutral but adversarial. First try hard to REFUTE the `
  + `ADVOCATE's case (missing preconditions, out-of-scope assumptions, unproven steps, hedging, `
  + `duplicates/accepted-risk, noise). Then deliver the honest verdict against the workspace rules. `
  + `You CANNOT run anything — judge only the argument and the EVIDENCE.\n`
  + `Verdict rules:\n`
  + `- REPORTABLE only if the EVIDENCE already contains an executed minimal PoC with REAL output, an `
  + `in-scope asset, and a concrete impact. If the PoC is only described/proposed (its output is NOT `
  + `in the EVIDENCE), you MUST return NEEDS_MORE_PROOF, never REPORTABLE.\n`
  + `- NEEDS_MORE_PROOF: plausible but something is missing — list exactly what, including `
  + `"execute the PoC and capture its output" whenever proof was only argued.\n`
  + `- DISCARD: out of scope, noise, duplicate/accepted-risk, or refuted.\n\n`
  + `=== DISCUSSION SO FAR ===\n${transcript}`,
  { label: 'skeptic: verdict', phase: 'Verdict', schema: VERDICT_SCHEMA },
)

return { topic: TOPIC, rebuttals: REBUTTALS, transcript, verdict }
