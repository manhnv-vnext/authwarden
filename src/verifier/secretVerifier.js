import https from 'https';

/**
 * Safe, read-only secret verifier.
 * Only checks authentication validity without performing any modifications.
 */

function checkHttps(options) {
  return new Promise((resolve) => {
    const req = https.request({
      ...options,
      timeout: 3000
    }, (res) => {
      res.resume(); // consume response data to free socket
      resolve({ status: res.statusCode });
    });

    req.on('error', () => resolve({ status: 0 }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 0 });
    });
    req.end();
  });
}

export async function verifySecret(finding) {
  const secret = finding.rawSecret;
  if (!secret) return null;

  try {
    // 1. GitHub Personal Access Token (supports both fine-grained and classic)
    if (finding.secretType === 'github_pat') {
      const res = await checkHttps({
        hostname: 'api.github.com',
        path: '/user',
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${secret}`,
          'User-Agent': 'AuthWarden-Scanner'
        }
      });
      if (res.status === 200) return { verified: true, message: 'Active GitHub Token (200 OK)' };
      if (res.status === 401) return { verified: false, message: 'Revoked / Invalid Token (401)' };
    }

    // 2. Stripe Secret Key
    if (finding.secretType === 'stripe_key') {
      const res = await checkHttps({
        hostname: 'api.stripe.com',
        path: '/v1/balance',
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${secret}`,
          'User-Agent': 'AuthWarden-Scanner'
        }
      });
      if (res.status === 200) return { verified: true, message: 'Active Stripe Key (200 OK)' };
      if (res.status === 401) return { verified: false, message: 'Invalid / Revoked Stripe Key' };
    }

    // 3. OpenAI Key
    if (finding.secretType === 'openai_key') {
      const res = await checkHttps({
        hostname: 'api.openai.com',
        path: '/v1/models',
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${secret}`,
          'User-Agent': 'AuthWarden-Scanner'
        }
      });
      if (res.status === 200) return { verified: true, message: 'Active OpenAI Key (200 OK)' };
      if (res.status === 401) return { verified: false, message: 'Invalid / Expired OpenAI Key' };
    }

    // 4. Anthropic API Key
    if (finding.secretType === 'anthropic_key') {
      const res = await checkHttps({
        hostname: 'api.anthropic.com',
        path: '/v1/models',
        method: 'GET',
        headers: {
          'x-api-key': secret,
          'anthropic-version': '2023-06-01',
          'User-Agent': 'AuthWarden-Scanner'
        }
      });
      if (res.status === 200) return { verified: true, message: 'Active Anthropic Key (200 OK)' };
      if (res.status === 401) return { verified: false, message: 'Invalid / Revoked Anthropic Key' };
    }

    // 5. Slack Bot / User Token
    if (finding.secretType === 'slack_token' && secret.startsWith('xoxb-')) {
      const res = await checkHttps({
        hostname: 'slack.com',
        path: '/api/auth.test',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${secret}`,
          'User-Agent': 'AuthWarden-Scanner'
        }
      });
      if (res.status === 200) return { verified: true, message: 'Active Slack Token (200 OK)' };
      if (res.status === 401 || res.status === 403) return { verified: false, message: 'Invalid / Revoked Slack Token' };
    }
  } catch {
    return null;
  }

  return null;
}
