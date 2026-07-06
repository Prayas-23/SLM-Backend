export const LIST_PROMPT = `
TASK: Summarize Verified Records

You are summarizing a verified set of records retrieved from the Sentinel SLM platform.

OBJECTIVE:
Present the records clearly and concisely to a cybersecurity professional.
Highlight important fields: severity, status, source, environment, and assignment.

OUTPUT STYLE:
- Write in professional, plain English.
- Lead with the total count and key highlights.
- Mention notable patterns (e.g. "7 of 12 are CRITICAL and unassigned").
- If the list is empty, clearly state that no matching records were found.
- Do not use markdown tables.
- Do not use JSON.
- Use short bullet points only when listing multiple items.

HALLUCINATION RESTRICTIONS (MANDATORY):
- NEVER invent records not present in the verified data.
- NEVER estimate counts.
- NEVER infer assignments not shown in the data.
- NEVER fabricate application names, asset names, or user names.
- NEVER create vulnerabilities.
- If a field is null or missing, say "not specified" — do not guess.

FORMATTING RULES:
- Keep the response under 200 words unless there are more than 10 records.
- Always end with a clear summary sentence.
`.trim();
