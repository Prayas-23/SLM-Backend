import { Injectable } from '@nestjs/common';
import { IEmailProvider } from './email.provider.interface';
import { ResendProvider } from './resend.provider';

/**
 * NotificationProviderFactory
 *
 * Returns the correct IEmailProvider implementation based on the
 * configured provider type key.
 *
 * NotificationService must NEVER instantiate providers directly.
 * This factory is the single point of provider resolution.
 *
 * To add a new provider in the future:
 *   1. Create a new class that implements IEmailProvider.
 *   2. Add a new `case` block below.
 *   3. No other file needs to change.
 */
@Injectable()
export class NotificationProviderFactory {
  /**
   * Returns an initialized IEmailProvider for the given provider type.
   *
   * @param providerType  String key from PlatformSetting: RESEND | SMTP | AWS_SES | SENDGRID
   * @param config        Flat config map sourced from PlatformSetting (notifications.*)
   */
  create(providerType: string, config: Record<string, string>): IEmailProvider {
    let provider: IEmailProvider;

    switch (providerType.toUpperCase()) {
      case 'RESEND':
        provider = new ResendProvider();
        break;
      // Future providers — add cases here without modifying NotificationService:
      // case 'SMTP':
      //   provider = new SmtpProvider();
      //   break;
      // case 'AWS_SES':
      //   provider = new AwsSesProvider();
      //   break;
      // case 'SENDGRID':
      //   provider = new SendGridProvider();
      //   break;
      default:
        // Unknown provider type — fall back to Resend with a log-friendly label
        provider = new ResendProvider();
        break;
    }

    provider.initialize(config);
    return provider;
  }
}
