const BASE_TEMPLATE = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; background-color: #f9fafb; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; margin-top: 20px; border: 1px solid #e5e7eb; }
    .header { background-color: #111827; padding: 20px; text-align: center; color: #ffffff; }
    .header h1 { margin: 0; font-size: 20px; letter-spacing: -0.5px; }
    .content { padding: 30px; }
    .details { background-color: #f3f4f6; padding: 15px; border-radius: 6px; margin: 20px 0; }
    .detail-row { margin-bottom: 8px; font-size: 14px; }
    .detail-label { font-weight: 600; color: #4b5563; display: inline-block; width: 120px; }
    .btn { display: inline-block; background-color: #2563eb; color: #ffffff !important; text-decoration: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; font-size: 14px; margin-top: 20px; }
    .footer { text-align: center; padding: 20px; font-size: 12px; color: #6b7280; border-top: 1px solid #e5e7eb; }
    .severity-CRITICAL { color: #dc2626; font-weight: bold; }
    .severity-HIGH { color: #ea580c; font-weight: bold; }
    .severity-MEDIUM { color: #d97706; font-weight: bold; }
    .severity-LOW { color: #2563eb; font-weight: bold; }
    .severity-INFORMATIONAL { color: #4b5563; font-weight: bold; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Sentinel SLM</h1>
    </div>
    <div class="content">
      {{CONTENT}}
    </div>
    <div class="footer">
      This is an automated notification from Sentinel SLM. Please do not reply directly to this email.
    </div>
  </div>
</body>
</html>
`;

export interface VulnTemplateContext {
  vulnId: string;
  title: string;
  severity: string;
  status: string;
  appName?: string;
  assetName?: string;
  assignedOwner?: string;
  link: string;
}

function buildDetailsHtml(ctx: VulnTemplateContext) {
  return `
    <div class="details">
      <div class="detail-row"><span class="detail-label">Vulnerability ID:</span> <strong>${ctx.vulnId}</strong></div>
      <div class="detail-row"><span class="detail-label">Severity:</span> <span class="severity-${ctx.severity}">${ctx.severity}</span></div>
      <div class="detail-row"><span class="detail-label">Status:</span> ${ctx.status}</div>
      ${ctx.appName ? `<div class="detail-row"><span class="detail-label">Application:</span> ${ctx.appName}</div>` : ''}
      ${ctx.assetName ? `<div class="detail-row"><span class="detail-label">Infrastructure:</span> ${ctx.assetName}</div>` : ''}
      <div class="detail-row"><span class="detail-label">Assigned To:</span> ${ctx.assignedOwner || 'Unassigned'}</div>
    </div>
  `;
}

export const EmailTemplates = {
  vulnerabilityCreated: (ctx: VulnTemplateContext) => {
    const content = `
      <h2>New Vulnerability Reported</h2>
      <p>A new vulnerability has been logged in Sentinel SLM that requires your attention.</p>
      <p><strong>${ctx.title}</strong></p>
      ${buildDetailsHtml(ctx)}
      <a href="${ctx.link}" class="btn">View Vulnerability</a>
    `;
    return BASE_TEMPLATE.replace('{{CONTENT}}', content);
  },

  vulnerabilityAssigned: (ctx: VulnTemplateContext) => {
    const content = `
      <h2>Vulnerability Assigned to You</h2>
      <p>You have been assigned to remediate a vulnerability in Sentinel SLM.</p>
      <p><strong>${ctx.title}</strong></p>
      ${buildDetailsHtml(ctx)}
      <a href="${ctx.link}" class="btn">View Vulnerability</a>
    `;
    return BASE_TEMPLATE.replace('{{CONTENT}}', content);
  },

  revalidationSubmitted: (ctx: VulnTemplateContext) => {
    const content = `
      <h2>Vulnerability Submitted for Revalidation</h2>
      <p>A vulnerability has been marked as patched and is awaiting security revalidation.</p>
      <p><strong>${ctx.title}</strong></p>
      ${buildDetailsHtml(ctx)}
      <a href="${ctx.link}" class="btn">Review Vulnerability</a>
    `;
    return BASE_TEMPLATE.replace('{{CONTENT}}', content);
  },

  revalidationFailed: (ctx: VulnTemplateContext) => {
    const content = `
      <h2>Revalidation Failed</h2>
      <p>The security team has rejected the patch for the following vulnerability. It requires further remediation.</p>
      <p><strong>${ctx.title}</strong></p>
      ${buildDetailsHtml(ctx)}
      <a href="${ctx.link}" class="btn">View Vulnerability</a>
    `;
    return BASE_TEMPLATE.replace('{{CONTENT}}', content);
  },

  vulnerabilityClosed: (ctx: VulnTemplateContext) => {
    const content = `
      <h2>Vulnerability Closed</h2>
      <p>The following vulnerability has been successfully remediated and closed.</p>
      <p><strong>${ctx.title}</strong></p>
      ${buildDetailsHtml(ctx)}
      <a href="${ctx.link}" class="btn">View Record</a>
    `;
    return BASE_TEMPLATE.replace('{{CONTENT}}', content);
  }
};
