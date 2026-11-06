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
    // 1. GitHub Personal Access Token
    if (finding.secretType === 'github_pat') {
      const res = await checkHttps({
        hostname: 'api.github.com',
        path: '/user',
        method: 'GET',
        headers: {
          'Authorization': `token ${secret}`,
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
  } catch {
    return null;
  }

  return null;
}
