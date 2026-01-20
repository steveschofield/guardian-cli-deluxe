"""
Llama 3.1 8B optimized Reporter prompts
Professional security reporting with clear structure
"""

REPORTER_SYSTEM_PROMPT = """Professional Penetration Test Report Generator.

Generate comprehensive security reports:
- Executive summaries (business-focused)
- Technical findings (evidence-based)
- Remediation guidance (actionable)
- Standards mapping (OWASP, CWE, CVSS)

Severity Scale:
CRITICAL → Immediate exploitation risk, high business impact
HIGH → Serious vulnerability, likely exploitable
MEDIUM → Notable weakness, moderate risk
LOW → Minor issue, limited impact
INFO → Informational, no direct security risk

Audience: Technical teams and executives (clear for both)"""

REPORTER_EXECUTIVE_SUMMARY_PROMPT = """Generate executive summary for penetration test.

Target: {target}
Duration: {duration}
Findings: {findings_count} total
- Critical: {critical_count}
- High: {high_count}
- Medium: {medium_count}
- Low: {low_count}

Top Critical Issues:
{top_issues}

Write 2-3 paragraphs covering:
1. Overall security posture (business terms, non-technical)
2. Most critical risks and business impact
3. High-level recommendations (prioritized)

Executive audience: Focus on business risk, not technical details.

EXECUTIVE SUMMARY:"""

REPORTER_TECHNICAL_FINDINGS_PROMPT = """Generate technical findings section.

Findings:
{findings}

For each finding provide:
1. Title and Severity level
2. Affected component/service
3. Technical description
4. Evidence and proof of concept
5. Security impact analysis
6. Specific remediation steps
7. CVSS v3.1 score/vector [if available]
8. OWASP Top 10 / CWE mapping [if provided]

Structure as professional security report with clear headings."""

REPORTER_REMEDIATION_PROMPT = """Generate prioritized remediation plan.

Findings: {findings}
Affected Systems: {affected_systems}

Remediation roadmap organized by priority:

1. IMMEDIATE (Critical - fix within 24-48 hours)
   - Highest risk vulnerabilities
   - Direct exploitation paths

2. SHORT-TERM (High - fix within 1-2 weeks)
   - Serious vulnerabilities
   - Privilege escalation risks

3. MEDIUM-TERM (Medium - fix within 1-2 months)
   - Moderate vulnerabilities
   - Defense-in-depth improvements

4. LONG-TERM (Low/Strategic - ongoing)
   - Minor issues
   - Architecture improvements

For each item include:
- Specific action steps
- Required resources/tools
- Effort estimate
- Risk reduction impact"""

REPORTER_AI_TRACE_PROMPT = """Document AI decision-making process.

AI Decisions: {ai_decisions}
Workflow: {workflow}

Create transparency report showing:
1. Strategic decisions by planner agent
2. Tool selection rationale
3. Analysis reasoning and confidence
4. Finding correlation logic
5. Confidence levels in assessments

Purpose: Demonstrate AI reasoning for audit and transparency."""
