// /api/oauth.js
import axios from 'axios';
import qs from 'qs';

const API_ENDPOINT = 'https://discord.com/api/v10';
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

// Change or set this via env if you want different scopes:
// example: "identify applications.commands gdm.join"
const REQUIRED_SCOPES = (process.env.REQUIRED_SCOPES || 'identify applications.commands gdm.join').trim();

function buildAuthorizeUrl() {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: REQUIRED_SCOPES.split(' ').join('+'),
  });
  return `https://discord.com/oauth2/authorize?${params.toString()}`;
}

export default async function handler(req, res) {
  const code = req.query.code;

  // If no code: redirect user to Discord authorize URL asking for the required scopes
  if (!code) {
    // sanity checks
    if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
      return res.status(500).json({
        error: 'server_misconfigured',
        message: 'CLIENT_ID, CLIENT_SECRET and REDIRECT_URI must be set in environment variables.'
      });
    }

    const authUrl = buildAuthorizeUrl();
    // Redirect user to Discord to authorize
    return res.writeHead(302, { Location: authUrl }).end();
  }

  // We have a code -> attempt token exchange
  try {
    const data = qs.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI
    });

    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };

    const tokenResp = await axios.post(`${API_ENDPOINT}/oauth2/token`, data, {
      headers,
      auth: { username: CLIENT_ID, password: CLIENT_SECRET },
      validateStatus: () => true // we'll handle status manually
    });

    if (tokenResp.status !== 200) {
      // Return Discord error details to help debugging (invalid_scope, invalid_grant, etc.)
      console.error('Discord token error:', tokenResp.status, tokenResp.data);
      return res.status(500).json({
        error: 'token_exchange_failed',
        status: tokenResp.status,
        details: tokenResp.data,
        authorize_url: buildAuthorizeUrl()
      });
    }

    const tokenData = tokenResp.data; // access_token, refresh_token, scope, expires_in, token_type
    const grantedScopes = (tokenData.scope || '').split(' ').filter(Boolean);

    // Verify required scopes were granted
    const required = REQUIRED_SCOPES.split(' ').filter(Boolean);
    const missing = required.filter(r => !grantedScopes.includes(r));

    if (missing.length > 0) {
      return res.status(400).json({
        error: 'missing_scopes',
        message: 'The token does not include required scopes.',
        required,
        granted: grantedScopes,
        missing,
        authorize_url: buildAuthorizeUrl()
      });
    }

    // Optional: fetch user info to confirm identify scope
    let user = null;
    try {
      const userResp = await axios.get(`${API_ENDPOINT}/users/@me`, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
        validateStatus: () => true
      });

      if (userResp.status === 200) user = userResp.data;
      else console.warn('Could not fetch /users/@me', userResp.status, userResp.data);
    } catch (e) {
      console.warn('Error fetching /users/@me:', e.message);
    }

    // Success: return token data + user info (or redirect to a success page)
    return res.status(200).json({
      ok: true,
      token: tokenData,
      user
    });
  } catch (error) {
    console.error('Unexpected error exchanging code:', error);
    return res.status(500).json({
      error: 'unexpected_error',
      message: error.message
    });
  }
}
