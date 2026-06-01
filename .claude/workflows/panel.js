export const meta = {
  name: 'panel',
  description: 'Multi-agent discussion panel that pressure-tests a candidate finding before reporting',
  phases: [
    { title: 'Discuss', detail: 'Round-robin debate over a shared transcript' },
    { title: 'Verdict', detail: 'Arbiter synthesizes a go/no-go on the finding' },
  ],
}

// ---- Inputs (override via the Workflow `args` value) -------------------------
// args may be:
//   - a string            -> treated as the topic/finding to discuss
//   - { topic, evidence, rounds, participants: [{name, brief}] }
// IMPORTANT: workflow scripts cannot read files. Paste the actual finding
// evidence (request/response, PoC + its real output, affected in-scope URL,
// relevant _RECON artifact excerpts) into `cfg.evidence` so the panel judges
// real material instead of speculating from a one-line topic.
const cfg = (typeof args === 'string') ? { topic: args } : (args ?? {})

const TOPIC = cfg.topic
  ?? 'Is the candidate finding a real, reportable, high-impact vulnerability? Prove it or discard it.'
const EVIDENCE = cfg.evidence
  ?? '(none supplied — agents must flag the absence of concrete evidence as a blocker, not assume it.)'
const ROUNDS = cfg.rounds ?? 3

// Default panel — tailored to this workspace's "prove it or discard it" discipline.
const PARTICIPANTS = cfg.participants ?? [
  {
    name: 'ANALYST',
    brief: 'You believe there is a real, high-impact vulnerability. Make the strongest concrete case: '
      + 'the exact attack path, the affected in-scope asset, a minimal PoC, and the business impact '
      + '("if X then attacker does Y to asset Z causing W"). No speculation — only what is provable.',
  },
  {
    name: 'SKEPTIC',
    brief: 'You are an adversarial triager. Try hard to REFUTE the finding: missing preconditions, '
      + 'out-of-scope assumptions, unproven steps, banned hedging ("might/could/may"), duplicates, '
      + 'accepted-risk, or noise (header/CSP/self-XSS). Demand a working minimal PoC. Default to '
      + '"not proven" when anything is hand-waved.',
  },
  {
    name: 'ARBITER',
    brief: 'You are neutral. Weigh ANALYST vs SKEPTIC strictly against the workspace rules: scope gate, '
      + 'concrete impact hypothesis, manual validation, minimal safe PoC, signal-over-noise. Identify '
      + 'exactly what is still needed to clear the bar, or confirm it already does.',
  },
]

const RULES = [
  'Workspace rules in force:',
  '- SCOPE GATE: only in-scope assets; flag any out-of-scope assumption.',
  '- Impact-first: a concrete, provable impact hypothesis is required.',
  '- No speculation: ban "might/could/may be exploitable" — proved or not.',
  '- Minimal, safe PoC required; no destructive/bulk actions.',
  '- Signal over noise: do not treat headers/CSP/self-XSS/version-disclosure as standalone findings.',
  '',
  'WHAT THIS PANEL CAN AND CANNOT DO: this is a reasoning panel — no agent here can',
  'run curl, hit the target, or execute a PoC. You judge ONLY the argument and the',
  'EVIDENCE supplied below. Treat any claim whose proof is not present in the EVIDENCE',
  'as UNPROVEN. "Reportable" means: the case clears the bar ASSUMING the cited PoC was',
  'actually executed and its real output appears in the EVIDENCE — never assume it was.',
].join('\n')

// ---- Discussion: round-robin over a shared transcript -----------------------
phase('Discuss')
let transcript = `TOPIC:\n${TOPIC}\n\n${RULES}\n\n=== EVIDENCE (the only concrete material; do not invent beyond it) ===\n${EVIDENCE}\n`

outer:
for (let round = 0; round < ROUNDS; round++) {
  for (const p of PARTICIPANTS) {
    const turn = await agent(
      `You are ${p.name}.\n${p.brief}\n\n`
      + `This is round ${round + 1} of ${ROUNDS}. Read the discussion so far and add ONLY your next turn `
      + `(concise, concrete, no role-playing of other participants).\n\n`
      + `=== DISCUSSION SO FAR ===\n${transcript}`,
      { label: `${p.name} r${round + 1}`, phase: 'Discuss' },
    )
    if (!turn) {                                  // agent skipped by the user
      log(`${p.name} r${round + 1} was skipped — ending discussion early and proceeding to verdict.`)
      break outer
    }
    transcript += `\n[${p.name} — round ${round + 1}]:\n${turn}\n`
  }
}

// ---- Verdict: structured go/no-go ------------------------------------------
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
    rationale: { type: 'string', description: 'Why this verdict, citing the strongest points from the debate.' },
    missing_to_prove: {
      type: 'array', items: { type: 'string' },
      description: 'Concrete gaps still blocking a report (empty if REPORTABLE).',
    },
    next_steps: {
      type: 'array', items: { type: 'string' },
      description: 'The exact next actions — e.g. which vuln-class skill to run, what PoC to capture.',
    },
  },
}

const verdict = await agent(
  `You are the panel chair. Read the full discussion and deliver the final, honest verdict on the finding.\n`
  + `You CANNOT run anything — judge only the argument and the EVIDENCE in the transcript.\n`
  + `Verdict rules:\n`
  + `- REPORTABLE only if the EVIDENCE already contains an executed minimal PoC with real output, `
  + `an in-scope asset, and a concrete impact. If the PoC is merely described/proposed but its `
  + `actual output is NOT in the EVIDENCE, you MUST return NEEDS_MORE_PROOF, not REPORTABLE.\n`
  + `- NEEDS_MORE_PROOF: the case is plausible but something above is missing — list exactly what, `
  + `including "execute the PoC and capture its output" whenever proof was only argued.\n`
  + `- DISCARD: out of scope, noise, duplicate/accepted-risk, or refuted.\n\n`
  + `=== FULL DISCUSSION ===\n${transcript}`,
  { label: 'chair: verdict', phase: 'Verdict', schema: VERDICT_SCHEMA },
)

return { topic: TOPIC, rounds: ROUNDS, participants: PARTICIPANTS.map(p => p.name), transcript, verdict }
