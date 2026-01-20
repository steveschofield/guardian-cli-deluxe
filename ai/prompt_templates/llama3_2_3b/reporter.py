"""
Optimized Reporter Agent prompts for Llama 3.2 3B
Compact formatting, clear structure, reduced verbosity
"""

REPORTER_SYSTEM_PROMPT = """Professional penetration test report generator.

Functions:
- Structure findings by severity/impact
- Business-focused executive summaries
- Technical detail sections
- Actionable remediation plans
- AI decision transparency

Severity Scale:
CRITICAL → immediate threat, high impact
HIGH → serious, likely exploitable
MEDIUM → notable weakness, moderate impact
LOW → minor issue, low impact
INFO → no direct security impact

Style: Professional, evidence-based, clear for technical + executive audiences."""

REPORTER_EXECUTIVE_SUMMARY_PROMPT = """Create executive summary for penetration test.

Target: {target} | Duration: {duration}
Findings: {findings_count} total ({critical_count} Critical, {high_count} High, {medium_count} Medium, {low_count} Low)

Top Issues:
{top_issues}

Write 2-3 paragraphs covering:
1. Security posture (business terms)
2. Critical risks + business impact
3. High-level recommendations

Audience: Executives (non-technical language)

EXECUTIVE SUMMARY:"""

REPORTER_TECHNICAL_FINDINGS_PROMPT = """Generate technical findings section.

Findings Data:
{findings}

For each finding include:
1. Title + Severity
2. Affected component
3. Technical description
4. Evidence/PoC
5. Impact analysis
6. Remediation steps (specific)
7. CVSS v3.1 [if available]
8. OWASP/CWE mapping [if provided]

Format: Professional report with clear headings."""

REPORTER_REMEDIATION_PROMPT = """Create prioritized remediation plan.

Findings: {findings}
Systems: {affected_systems}

Organize by priority:
1. Quick Wins - easy + high impact
2. Critical - fix immediately
3. Medium-term - schedule soon
4. Long-term - strategic improvements

Each item needs:
- Action steps (specific)
- Resources/tools required
- Effort estimate
- Security impact

Format: Prioritized action plan."""

REPORTER_AI_TRACE_PROMPT = """Document AI decision-making for transparency.

Decisions: {ai_decisions}
Workflow: {workflow}

Show:
1. Planner strategic decisions + rationale
2. Tool selection reasoning
3. Analysis logic
4. Finding correlation process
5. Confidence levels

Purpose: Audit trail showing AI reasoning throughout test."""
