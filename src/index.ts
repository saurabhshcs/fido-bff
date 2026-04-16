import { Issuer } from 'openid-client';
import { config } from './config';
import { createApp } from './app';

async function main(): Promise<void> {
  let client;

  if (config.mock.enabled) {
    // In mock mode, skip OIDC discovery — the openid-client is never used.
    // We still need to pass a Client instance, so we use a minimal placeholder.
    console.log('[BFF] Mock auth enabled — skipping Asgardeo OIDC discovery');
    client = {} as InstanceType<typeof Issuer.prototype.Client>;
  } else {
    const discoveryUrl = `${config.asgardeo.baseUrl}/oauth2/token/.well-known/openid-configuration`;
    console.log(`[BFF] Discovering OIDC config at ${discoveryUrl}...`);
    const issuer = await Issuer.discover(discoveryUrl);
    client = new issuer.Client({
      client_id: config.asgardeo.clientId,
      client_secret: config.asgardeo.clientSecret,
      redirect_uris: [config.asgardeo.redirectUri],
      response_types: ['code'],
      token_endpoint_auth_method: 'none', // Public client using PKCE — no client secret required
    });
    console.log('[BFF] OIDC discovery complete');
  }

  const app = createApp(client);

  app.listen(config.port, () => {
    console.log(`[BFF] Listening on http://localhost:${config.port}`);
    console.log(`[BFF] Environment: ${config.nodeEnv}`);
    if (config.mock.enabled) {
      console.log(`[BFF] Mock user: ${config.mock.email} / ${config.mock.displayName}`);
    }
  });
}

main().catch(err => {
  console.error('[BFF] Fatal startup error:', err);
  process.exit(1);
});
