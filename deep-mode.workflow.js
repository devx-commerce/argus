export const meta = {
  name: 'argus-deep',
  description: 'argus deep mode: investigate each HIGH/CRIT host-scan finding in parallel, then synthesize a triage verdict',
  phases: [
    { title: 'Investigate', detail: 'one read-only investigator per finding' },
    { title: 'Synthesize', detail: 'aggregate verdicts into a triage summary' },
  ],
}

// args: an array of finding objects {severity, layer, category, title, evidence},
// or { findings: [...] }. The argus skill parses findings.tsv (HIGH/CRIT rows) and
// passes them here. Workflow scripts have no filesystem access, but each investigator
// agent does - it reads the evidence path (never executes it).

const raw = Array.isArray(args) ? args : (args && args.findings) || []
const CAP = 9                                   // keep the fan-out under 10 agents
const findings = raw.slice(0, CAP)
if (raw.length > CAP) log(`capping deep investigation at ${CAP} of ${raw.length} findings (rerun on the rest)`)
if (!findings.length) { log('no HIGH/CRIT findings passed to deep mode'); return { verdicts: [], summary: 'nothing to investigate' } }

const VERDICT = {
  type: 'object',
  properties: {
    title: { type: 'string' },
    is_true_positive: { type: 'boolean' },
    confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    classification: { type: 'string', enum: ['confirmed_compromise', 'likely_compromise', 'suspicious_review', 'benign_namesake', 'allowlisted_tooling', 'test_fixture', 'needs_human'] },
    rationale: { type: 'string' },
    recommended_action: { type: 'string' },
  },
  required: ['title', 'is_true_positive', 'classification', 'rationale', 'recommended_action'],
}

phase('Investigate')
const verdicts = (await parallel(findings.map((f, i) => () =>
  agent(
    [
      'You are a host-forensics investigator verifying one finding from the argus read-only malware scanner.',
      'STRICTLY READ-ONLY: you may read files, list directories, inspect process/network state, and check package metadata.',
      'NEVER modify, delete, quarantine, kill a process, or run a suspect binary/package. Do not run pip/npm/the vendor CLI against suspect paths.',
      '',
      `Finding #${i + 1}:`,
      `  severity: ${f.severity || '?'}`,
      `  layer/category: ${f.layer || '?'} / ${f.category || '?'}`,
      `  title: ${f.title || '?'}`,
      `  evidence: ${f.evidence || '?'}`,
      '',
      'Context: this is the October 2026 supply-chain wave (LiteLLM 1.107.0, Tensorlake 0.5.144, SubQuery @subql/common 5.8.3, OVHcloud CLI backdoor, Rank Math PRO 3.0.123) plus general host-compromise checks. The host owner runs offensive security tooling, so weigh whether a hit is expected tooling (see the skill allowlist), a benign file that merely shares a name, a leftover test fixture, or a real indicator. Correlate: a real compromise usually shows more than one signal (the IOC file AND a live connection AND persistence).',
      'Open the evidence path read-only and decide. Give a concrete true-positive-or-not verdict with a specific rationale and a read-only recommended action (what the owner should check or rotate; never auto-remediation).',
    ].join('\n'),
    { label: `investigate:${(f.category || 'finding')}#${i + 1}`, phase: 'Investigate', schema: VERDICT, agentType: 'general-purpose' }
  )
))).filter(Boolean)

phase('Synthesize')
const summary = await agent(
  [
    'You are aggregating argus deep-mode verdicts into a single triage summary for the host owner.',
    'Here are the per-finding verdicts as JSON:',
    JSON.stringify(verdicts, null, 2),
    '',
    'Produce a concise triage: (1) confirmed or likely compromises first, with the exact recommended read-only action for each; (2) items needing a human decision; (3) items cleared as benign/allowlisted/fixture. If any confirmed compromise involves the Oct 2026 credential-stealers, state plainly that credentials on this host should be treated as exposed and rotated from a clean machine. Recommend only; do not instruct auto-remediation. No emojis, no em dashes, no bold.',
  ].join('\n'),
  { label: 'synthesize', phase: 'Synthesize' }
)

return { count: verdicts.length, verdicts, summary }
