# Ollama LLM Prompt Optimization Analysis

## Executive Summary

After reviewing the prompt templates for Analyst, Planner, and Reporter agents, I've identified several optimization opportunities specific to Ollama and local LLM deployment. The current prompts are well-structured but can be optimized for better performance with smaller open-source models.

## Current Prompt Assessment

### Strengths
1. **Clear Structure**: All prompts have well-defined roles and objectives
2. **Evidence-Based**: Strong emphasis on grounding responses in actual tool output
3. **Format Specifications**: Clear output format requirements
4. **Concise System Prompts**: Relatively short and focused (compared to originals)

### Areas for Ollama Optimization

## 1. Analyst Prompts (`ai/prompt_templates/analyst.py`)

### Current Issues for Ollama:

#### A. `ANALYST_SYSTEM_PROMPT` (Lines 6-28)
**Current Length**: ~190 words

**Optimization Opportunities**:
- **Redundancy**: "Critical rules" section repeats concepts from "Core functions"
- **Verbosity**: Framework steps could be condensed
- **Format**: Bullet points work well, but numbered lists are slightly more token-efficient

**Recommended Optimization**:
```python
ANALYST_SYSTEM_PROMPT = """Security Analyst for Guardian penetration testing tool.

Role: Extract security findings from scan outputs with evidence-based analysis.

Rules:
1. Base findings ONLY on concrete evidence from output
2. Quote exact snippets as proof
3. Never infer vulnerabilities without proof
4. Severity: Critical/High/Medium/Low/Info
5. Generic headers (CORS, CSP) = Low/Info unless tool flags them
6. Filter false positives

Process: Evidence → Exploitability → Impact → Validation → Mitigation"""
```

**Token Reduction**: ~60% (190 → 75 words)
**Clarity**: Maintained or improved

#### B. `ANALYST_INTERPRET_PROMPT` (Lines 30-60)
**Current Length**: ~140 words

**Issues**:
- Asks for 6 separate analysis points (could overwhelm smaller models)
- Format template is verbose
- CVSS/CWE/OWASP fields may not always be applicable

**Optimization Strategy**:
```python
ANALYST_INTERPRET_PROMPT = """Analyze this security tool output for vulnerabilities.

Tool: {tool} | Target: {target}
Command: {command}

OUTPUT:
{output}

Extract findings using this format:

[SEVERITY] Title
Evidence: "quoted from output"
Impact: security implications
Fix: specific remediation steps
CVSS: score (vector) [if applicable]
CWE/OWASP: IDs [if known]

If no concrete evidence exists, respond: "No security findings in this output."

Summary: Overall assessment"""
```

**Benefits**:
- Reduced from 140 to ~80 words (43% reduction)
- Clearer structure for parsing
- Optional fields clearly marked
- Direct instruction about no-findings case

#### C. `ANALYST_CORRELATION_PROMPT` (Lines 62-80)
**Current**: Well-structured but could be more directive

**Optimization**:
```python
ANALYST_CORRELATION_PROMPT = """Correlate security findings across multiple tools.

Target: {target}

Results:
{tool_results}

Provide:
1. Cross-tool patterns and connections
2. Attack chain: Entry → Pivot → Impact
3. Priority ranking by exploitability
4. Risk assessment: Low/Medium/High/Critical
5. Next recommended tests

Focus: How do vulnerabilities combine to create attack paths?"""
```

**Token Reduction**: ~25% (reduces verbose explanations)

#### D. `ANALYST_FALSE_POSITIVE_PROMPT` (Lines 82-102)
**Current**: Clear format, minimal optimization needed

**Minor Optimization**:
```python
ANALYST_FALSE_POSITIVE_PROMPT = """Evaluate if this is a false positive.

Finding: {tool} - {severity}
Description: {description}
Evidence: {evidence}
Context: {context}

Analyze:
- True positive confidence: 0-100%
- Supporting/refuting evidence
- False positive conditions
- Decision: KEEP / DISCARD / VERIFY_MANUALLY

Format:
CONFIDENCE: XX%
ANALYSIS: reasoning
DECISION: action"""
```

## 2. Planner Prompts (`ai/prompt_templates/planner.py`)

### Current Issues:

#### A. `PLANNER_SYSTEM_PROMPT` (Lines 6-20)
**Current**: Concise and effective (already well-optimized)

**Recommendation**: No changes needed (only ~50 words)

#### B. `PLANNER_DECISION_PROMPT` (Lines 22-52)
**Current Length**: ~140 words

**Critical Issue for Ollama**:
- Requires STRICT JSON output
- Many local models struggle with pure JSON without markdown
- Verbose context setup

**Optimization**:
```python
PLANNER_DECISION_PROMPT = """Select next penetration test action.

STATE:
Phase: {phase} | Target: {target}
Completed: {completed_actions}
Findings: {findings}

AVAILABLE ACTIONS:
{available_actions}

Decision criteria:
1. Logical next step based on findings
2. Maximum attack surface coverage
3. Avoid redundancy
4. Highest risk/priority first

Respond in JSON (no markdown):
{{"next_action": "exact action token", "parameters": "specific params", "expected_outcome": "brief outcome"}}

Note: Use exact action tokens from AVAILABLE ACTIONS list."""
```

**Benefits**:
- Reduced 140 → 90 words (36% reduction)
- Clearer JSON expectation
- More explicit about no markdown formatting
- Numbered criteria easier to follow

#### C. `PLANNER_ANALYSIS_PROMPT` (Lines 54-72)
**Optimization**:
```python
PLANNER_ANALYSIS_PROMPT = """Strategic analysis of penetration test results.

Target: {target} | Phase: {phase}

Findings:
{findings_summary}

Tools Used:
{tools_executed}

Provide:
1. Attack surface: exposed services, entry points
2. Critical vulnerabilities (ranked)
3. Identified attack vectors
4. Next phase recommendations
5. Overall risk: Critical/High/Medium/Low

Focus on actionable intelligence and critical issues."""
```

**Token Reduction**: ~20%

## 3. Reporter Prompts (`ai/prompt_templates/reporter.py`)

### Current Issues:

#### A. `REPORTER_SYSTEM_PROMPT` (Lines 6-35)
**Current**: Well-structured, but verbose

**Optimization**:
```python
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
```

**Token Reduction**: ~40% (maintains all key information)

#### B. `REPORTER_EXECUTIVE_SUMMARY_PROMPT` (Lines 37-59)
**Current**: Clear but could be more directive

**Optimization**:
```python
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
```

**Benefits**:
- Condensed metadata format
- More explicit structure
- Clearer audience reminder

#### C. `REPORTER_TECHNICAL_FINDINGS_PROMPT` (Lines 61-77)
**Optimization**:
```python
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
```

**Token Reduction**: ~15%

#### D. `REPORTER_REMEDIATION_PROMPT` (Lines 79-100)
**Already well-optimized**, minimal changes needed

**Minor refinement**:
```python
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
```

#### E. `REPORTER_AI_TRACE_PROMPT` (Lines 102-118)
**Optimization**:
```python
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
```

## 4. Ollama-Specific Optimization Strategies

### A. Token Efficiency
**Priority**: High for models with smaller context windows

**Techniques**:
1. **Use symbols over words**: "→" instead of "leads to", "|" for separators
2. **Abbreviate metadata**: "Sev:" instead of "Severity:"
3. **Remove filler words**: "the", "a", "an" where context is clear
4. **Compact formatting**: Single-line where possible

**Example**:
```
Before: "The severity of this finding is: Critical"
After: "Severity: CRITICAL"
```

### B. Structured Output Handling
**Issue**: Many Ollama models wrap JSON in markdown code fences

**Solution**: Add explicit anti-markdown instructions
```python
prompt += "\n\nIMPORTANT: Output raw JSON only. No markdown, no code fences, no explanations."
```

**Better Solution**: Use regex post-processing to extract JSON:
```python
import re
import json

def extract_json(response):
    # Try direct parse first
    try:
        return json.loads(response)
    except:
        pass

    # Extract from markdown code fences
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
    if match:
        return json.loads(match.group(1))

    # Extract raw JSON object
    match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response, re.DOTALL)
    if match:
        return json.loads(match.group(0))

    raise ValueError("No valid JSON found in response")
```

### C. Context Window Management
**Ollama Models**:
- Llama 3 (8B): 8K context
- Llama 3 (70B): 8K context
- Mistral 7B: 8K context
- Qwen 2.5: 32K context

**Strategy**:
1. **Truncate tool output** before sending (already done in code)
2. **Summarize context** instead of full history
3. **Use references** instead of repeating data

**Example Context Compression**:
```python
# Instead of full tool results:
TOOL RESULTS (5000 tokens):
httpx: found 50 URLs...
nmap: 15 ports open...
...

# Use summary:
TOOL RESULTS (500 tokens):
httpx: 50 URLs (3 suspicious)
nmap: 15 open ports (SSH, HTTP, HTTPS critical)
nuclei: 2 HIGH severity findings
```

### D. Response Format Optimization
**Issue**: Verbose formatting instructions take tokens

**Solution**: Use templating hints
```python
# Before (60 tokens):
"""Provide your response in the following format:
FINDINGS:
- [SEVERITY] description
  Evidence: evidence text
  Impact: impact description
  Recommendation: fix steps"""

# After (35 tokens):
"""Format:
[SEVERITY] title
Evidence: "quote"
Impact: description
Fix: steps"""
```

### E. Few-Shot Examples for Consistency
**Problem**: Local models need more guidance than GPT-4

**Solution**: Add 1-2 examples directly in prompts (only for critical formats)
```python
ANALYST_INTERPRET_PROMPT = """...format instructions...

Example:
[HIGH] SQL Injection in login form
Evidence: "mysql_real_escape_string() missing on username parameter"
Impact: Database compromise, data exfiltration
Fix: Use parameterized queries, add input validation
CVSS: 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L)

Now analyze:
{output}"""
```

**Tradeoff**: Adds ~50 tokens but significantly improves output consistency

## 5. Model-Specific Recommendations

### For Llama 3 (8B/70B)
- **Strengths**: Instruction following, reasoning
- **Weaknesses**: JSON formatting, verbose responses
- **Optimization**: Use explicit format templates, add JSON extraction logic

### For Mistral 7B
- **Strengths**: Concise responses, good at structured output
- **Weaknesses**: Less nuanced reasoning
- **Optimization**: Focus on direct questions, avoid open-ended analysis

### For Qwen 2.5
- **Strengths**: Large context (32K), good reasoning
- **Weaknesses**: Instruction adherence varies
- **Optimization**: Use clear delimiters, explicit output format

### For DeepSeek Coder
- **Strengths**: Code understanding, technical details
- **Weaknesses**: May over-explain
- **Optimization**: Request concise output explicitly

## 6. Implementation Priority

### High Priority (Immediate Impact)
1. **Planner JSON output** - Critical for workflow
2. **Analyst evidence extraction** - Core functionality
3. **Token reduction in system prompts** - Universal benefit

### Medium Priority (Performance Improvement)
4. **Reporter formatting** - Better report quality
5. **Context compression** - Handles more tool output
6. **Few-shot examples** - Consistency boost

### Low Priority (Nice to Have)
7. **Symbol optimization** - Marginal token savings
8. **Model-specific tuning** - Only if using specific model

## 7. Testing Recommendations

### Benchmarking Process
1. **Create test dataset**: 10 sample tool outputs
2. **Baseline metrics**:
   - Token count (input/output)
   - Response time
   - Output quality score (1-5)
   - Format compliance rate
3. **Test each optimization**:
   - Original prompt
   - Optimized prompt
   - Compare metrics
4. **Validate with different models**:
   - Llama 3 8B
   - Mistral 7B
   - Qwen 2.5 7B

### Quality Metrics
- **Accuracy**: Does it find real vulnerabilities?
- **Precision**: False positive rate
- **Recall**: False negative rate
- **Format**: Follows specified output format
- **Conciseness**: Avoids unnecessary verbosity

## 8. Configuration Recommendations

### Add Ollama-Specific Config Section
```yaml
ai:
  provider: ollama
  model: llama3
  temperature: 0.2
  context_window: 8192

  # Ollama optimizations
  ollama_optimizations:
    enabled: true
    use_compact_prompts: true
    json_extraction: true  # Auto-extract JSON from markdown
    max_input_tokens: 6000  # Leave room for output
    truncate_strategy: "smart"  # vs "hard_limit"
```

## 9. Estimated Impact

### Token Savings
- **Analyst prompts**: 35-60% reduction
- **Planner prompts**: 20-36% reduction
- **Reporter prompts**: 15-40% reduction

### Performance Improvement (Estimated)
- **Response time**: 15-30% faster (fewer tokens to generate)
- **Context capacity**: 30-50% more tool output fits
- **Consistency**: 20-40% better format compliance

### Cost Savings
- **Latency**: Shorter prompts = faster inference
- **Resource usage**: Less memory, lower compute
- **Throughput**: More requests per minute

## 10. Risks and Mitigation

### Risk: Output Quality Degradation
**Mitigation**:
- A/B test each optimization
- Keep original prompts as fallback
- Use quality scoring

### Risk: Format Breaking Changes
**Mitigation**:
- Comprehensive regex parsing
- Graceful degradation
- Error logging and recovery

### Risk: Model-Specific Failures
**Mitigation**:
- Test across multiple models
- Configurable prompt variants
- Auto-detection and adjustment

## Conclusion

The current prompts are already relatively well-optimized compared to the originals. However, significant gains (20-60% token reduction) are possible with focused optimization for Ollama/local LLMs while maintaining or improving output quality.

**Recommended Next Steps**:
1. Implement high-priority optimizations
2. Create testing framework
3. Benchmark with Llama 3 and Mistral
4. Iterate based on results
5. Add model-specific prompt variants

**Key Principle**: Optimize for token efficiency without sacrificing clarity or output quality.
