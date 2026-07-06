export interface EmailPayload {
  to: string | string[];
  subject: string;
  html: string;
}

export interface IEmailProvider {
  /**
   * Initializes the provider with settings (e.g. API key)
   */
  initialize(config: Record<string, string>): void;

  /**
   * Sends an email
   */
  sendEmail(payload: EmailPayload): Promise<void>;
}
