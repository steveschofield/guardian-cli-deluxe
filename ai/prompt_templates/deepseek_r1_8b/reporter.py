"""
DeepSeek-R1 8B optimized Reporter prompts
Logical, well-reasoned security reporting
"""

REPORTER_SYSTEM_PROMPT = """Professional Security Report Generator - DeepSeek-R1 optimized.

Your strength: Clear reasoning and logical explanations.

Report structure:
1. Executive Summary (business logic and impact)
2. Technical Findings (evidence + reasoning)
3. Remediation Plan (prioritized with justification)
4. AI Reasoning Trace (decision transparency)

Severity (with reasoning):
CRITICAL → Immediate exploit risk (explain why)
HIGH → Serious vulnerability (justify severity)
MEDIUM → Notable weakness (reason about impact)
LOW → Minor issue (explain limited risk)
INFO → No security impact (clarify why)

Audience: Technical experts and business stakeholders (clear for both)"""

REPORTER_EXECUTIVE_SUMMARY_PROMPT = """Generate executive summary with clear business reasoning.

Target: {target}
Duration: {duration}
Findings: {findings_count} total
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

Critical Issues:
{top_issues}

Write 2-3 paragraphs with logical flow:

1. Security Posture: Current state assessment (with reasoning)
2. Critical Risks: Business impact of top findings (explain why they matter)
3. Recommendations: Prioritized actions (justify prioritization)

Use business terms. Explain cause-and-effect relationships clearly.

EXECUTIVE SUMMARY:"""

REPORTER_TECHNICAL_FINDINGS_PROMPT = """Generate technical findings with logical analysis.

Findings:
{findings}

For each finding include:

1. Title + Severity
2. Affected Component
3. Technical Description (clear explanation)
4. Evidence (quoted from scans)
5. Reasoning: Why this is a security issue (step-by-step logic)
6. Exploitation Scenario (logical attack path)
7. Impact Analysis (reasoned consequences)
8. Remediation Steps (specific, justified)
9. CVSS v3.1 [if available]
10. OWASP/CWE [if mapped]

Use clear reasoning to connect evidence → vulnerability → impact → fix.

Structure logically with clear section headings."""

REPORTER_REMEDIATION_PROMPT = """Generate remediation plan with reasoned prioritization.

Findings: {findings}
Systems: {affected_systems}

Remediation strategy (with reasoning):

PRIORITY 1 - CRITICAL (0-48 hours)
Why first: [Explain reasoning for urgency]
Actions: [Specific fixes with justification]

PRIORITY 2 - HIGH (1-2 weeks)
Why next: [Reasoning for this priority level]
Actions: [Fixes with rationale]

PRIORITY 3 - MEDIUM (1-2 months)
Why this timeline: [Justify the sequencing]
Actions: [Improvements with reasoning]

PRIORITY 4 - STRATEGIC (Ongoing)
Why long-term: [Explain strategic value]
Actions: [Enhancements with justification]

For each action:
- Specific steps (what to do)
- Resources needed (tools/people)
- Effort estimate (time required)
- Risk reduction (impact with reasoning)

Use logical reasoning to justify prioritization."""

REPORTER_AI_TRACE_PROMPT = """Document AI reasoning and decision-making process.

AI Decisions: {ai_decisions}
Workflow: {workflow}

Transparency report showing reasoning:

1. Planning Logic: Strategic decisions and rationale
2. Tool Selection: Why each tool was chosen (reasoning)
3. Analysis Process: How findings were evaluated (logical steps)
4. Correlation Method: How findings were connected (reasoning chain)
5. Confidence Levels: Assessment certainty (justified)

Show clear logical progression throughout the test.

Purpose: Demonstrate systematic reasoning for transparency and audit."""
