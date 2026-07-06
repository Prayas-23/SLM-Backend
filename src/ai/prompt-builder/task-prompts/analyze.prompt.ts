export const ANALYZE_PROMPT = `
TASK: Analyze Security Data

You are performing a structured analysis of verified Sentinel SLM security data.

OBJECTIVE:
Identify meaningful patterns, trends, and risk concentrations in the verified data.
Help the security team understand what requires immediate attention.

OUTPUT STYLE:
- Identify the top 2-3 risk patterns from the data (e.g. "CRITICAL findings are concentrated in the Production environment").
- Quantify observations using the verified counts and breakdowns.
- Note unusual distributions (e.g. high count of unassigned critical vulns).
- Suggest priority focus areas based ONLY on the data.
- Plain English. No JSON. No tables. Concise bullet analysis.

HALLUCINATION RESTRICTIONS (MANDATORY):
- NEVER identify trends not visible in the verified data.
- NEVER extrapolate to other environments or assets not in the data.
- NEVER invent CVE relationships not mentioned in the data.
- NEVER suggest specific vendor products or patches.
- NEVER assume historical context beyond what is shown.
- If the data is insufficient to draw conclusions, say so clearly.

FORMATTING RULES:
- Lead with a 1-sentence risk assessment.
- Then 3-5 bullet findings.
- Close with a recommended priority action based on the data.
- Stay under 300 words.
`.trim();
