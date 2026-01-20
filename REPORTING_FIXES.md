# Reporting Fixes Summary

## 1. Analyst Agent - Multiple Findings Extraction

**Problem**: Reports showed extensive analysis in "AI Decision Trace" but only 1 finding in "Findings Summary". The Analyst was generating detailed analysis but the parser couldn't extract multiple findings.

**Root Cause**: 
- LLM generated unstructured analysis text instead of structured findings
- Parser (`_parse_findings()`) couldn't split unstructured text into separate Finding objects

**Solution**:
- **Updated prompt** (`ai/prompt_templates/analyst.py`): Request structured format with `### FINDING:` markers for EACH vulnerability
- **Rewrote parser** (`core/analyst_agent.py`): Split response by `### FINDING:` markers and extract structured fields (SEVERITY, EVIDENCE, CVSS, CWE, OWASP, IMPACT, RECOMMENDATION)

**Result**: Each vulnerability now extracted as separate Finding object with proper counts in reports.

---

## 2. Prompt Optimization for Bedrock/Sonnet 4.5

**Changes**:
- **Planner**: Moved JSON format to TOP, removed redundant "STRICT JSON" warnings, simplified decision criteria
- **Analyst**: Condensed system prompt (15→8 lines), moved output format to TOP, removed verbose instructions
- **Reporter**: Condensed system prompt (25→8 lines), removed redundant explanations

**Rationale**: Sonnet 4.5 follows initial instructions precisely and doesn't need verbose hand-holding.

---

## 3. DNS Enumeration for IP Targets

**Problem**: Recon workflow had no DNS enumeration for IP targets (reverse lookups, zone transfers).

**Solution**: Added `dnsrecon` as first step in `workflows/recon.yaml`:
```yaml
- name: dns_enumeration
  type: tool
  tool: dnsrecon
  objective: "Perform DNS enumeration including reverse lookups and zone transfers"
  parameters:
    scan_type: "std"
```

---

## 4. SSL Certificate SAN Extraction

**Problem**: testssl.sh tool only extracted CN and expiry, not Subject Alternative Names (SAN).

**Solution**: Added SAN extraction in `tools/testssl.py`:
- Extract `cert_subjectAltName` from testssl JSON output
- Display "no san attributes values found" if SAN field is empty/missing

**Result**: Certificate info now includes all SAN domains for expanded attack surface discovery.

---

## Files Modified

1. `ai/prompt_templates/analyst.py` - Structured finding format
2. `ai/prompt_templates/planner.py` - Optimized for Sonnet 4.5
3. `ai/prompt_templates/reporter.py` - Optimized for Sonnet 4.5
4. `core/analyst_agent.py` - Multi-finding parser
5. `workflows/recon.yaml` - Added DNS enumeration
6. `tools/testssl.py` - Added SAN extraction

---

## Impact

- **Accurate finding counts**: Reports now show correct number of vulnerabilities identified
- **Better AI responses**: Cleaner, more structured output from LLM agents
- **Complete reconnaissance**: DNS enumeration for IP targets
- **Enhanced cert analysis**: SAN domains discovered for additional testing targets
