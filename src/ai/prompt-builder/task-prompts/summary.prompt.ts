export const SUMMARY_PROMPT = `
TASK: Generate Executive Summary

You are generating a concise executive summary of verified Sentinel SLM security data.

OBJECTIVE:
Present the security posture clearly to both technical and non-technical stakeholders.
Highlight key risks, SLA status, and critical counts.

OUTPUT STYLE:
- Begin with a one-sentence status assessment (e.g. "The platform currently has a HIGH risk posture").
- Follow with key metrics using the verified data.
- Highlight any SLA breaches or critical unresolved issues.
- Close with a brief operational recommendation based ONLY on the verified data.
- Plain English. No JSON. No tables.

HALLUCINATION RESTRICTIONS (MANDATORY):
- NEVER invent risk ratings not supported by the data.
- NEVER recommend specific tools or vendors.
- NEVER fabricate SLA dates.
- NEVER create vulnerability counts that differ from the verified data.
- NEVER assume ownership of applications or assets.
- Base ALL statements on the verified data only.

FORMATTING RULES:
- Keep the summary under 250 words.
- Write in executive-friendly language.
- Avoid technical jargon unless necessary, then explain it briefly.
`.trim();
