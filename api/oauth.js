// /api/oauth.js
import axios from 'axios';
import qs from 'qs';

const API_ENDPOINT = 'https://discord.com/api/v10';
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

// Where to redirect users after successful OAuth (Discord app or custom success page)
const SUCCESS_REDIRECT_URL = process.env.SUCCESS_REDIRECT_URL || 'https://discord.com/app';

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

// Safe logging function that doesn't expose sensitive data
function logSecurely(message, data = {}) {
  const safeData = { ...data };
  
  // Remove sensitive fields
  if (safeData.access_token) safeData.access_token = '[REDACTED]';
  if (safeData.refresh_token) safeData.refresh_token = '[REDACTED]';
  if (safeData.token) {
    safeData.token = {
      ...safeData.token,
      access_token: '[REDACTED]',
      refresh_token: '[REDACTED]'
    };
  }
  if (safeData.user?.email) safeData.user.email = '[REDACTED]';
  
  console.log(message, safeData);
}

export default async function handler(req, res) {
  const code = req.query.code;

  // If no code: redirect user to Discord authorize URL asking for the required scopes
  if (!code) {
    // sanity checks
    if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
      console.error('OAuth misconfiguration: Missing required environment variables');
      return res.status(500).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Configuration Error</title>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .error { background: #fee; border: 1px solid #fcc; padding: 20px; border-radius: 5px; }
          </style>
        </head>
        <body>
          <div class="error">
            <h2>⚠️ Configuration Error</h2>
            <p>The OAuth service is not properly configured. Please contact the administrator.</p>
          </div>
        </body>
        </html>
      `);
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
      // Log error securely (no sensitive data)
      logSecurely('Discord token exchange failed:', {
        status: tokenResp.status,
        error: tokenResp.data?.error,
        error_description: tokenResp.data?.error_description
      });
      
      return res.status(500).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Authorization Failed</title>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .error { background: #fee; border: 1px solid #fcc; padding: 20px; border-radius: 5px; }
            .retry-btn { background: #5865f2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; display: inline-block; margin-top: 10px; }
          </style>
        </head>
        <body>
          <div class="error">
            <h2>❌ Authorization Failed</h2>
            <p>There was an error during the authorization process. Please try again.</p>
            <a href="${buildAuthorizeUrl()}" class="retry-btn">Try Again</a>
          </div>
        </body>
        </html>
      `);
    }

    const tokenData = tokenResp.data; // access_token, refresh_token, scope, expires_in, token_type
    const grantedScopes = (tokenData.scope || '').split(' ').filter(Boolean);

    // Verify required scopes were granted
    const required = REQUIRED_SCOPES.split(' ').filter(Boolean);
    const missing = required.filter(r => !grantedScopes.includes(r));

    if (missing.length > 0) {
      logSecurely('Missing required scopes:', { required, granted: grantedScopes, missing });
      
      return res.status(400).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Missing Permissions</title>
          <meta charset="utf-8">
          <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .error { background: #fee; border: 1px solid #fcc; padding: 20px; border-radius: 5px; }
            .retry-btn { background: #5865f2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; display: inline-block; margin-top: 10px; }
            ul { margin: 10px 0; }
          </style>
        </head>
        <body>
          <div class="error">
            <h2>⚠️ Missing Permissions</h2>
            <p>The application requires additional permissions that were not granted:</p>
            <ul>
              ${missing.map(scope => `<li>${scope}</li>`).join('')}
            </ul>
            <p>Please authorize again and make sure to grant all required permissions.</p>
            <a href="${buildAuthorizeUrl()}" class="retry-btn">Authorize Again</a>
          </div>
        </body>
        </html>
      `);
    }

    // Optional: fetch basic user info for logging (without exposing it)
    let userInfo = null;
    try {
      const userResp = await axios.get(`${API_ENDPOINT}/users/@me`, {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
        validateStatus: () => true
      });

      if (userResp.status === 200) {
        userInfo = userResp.data;
        // Log successful authorization (safely)
        logSecurely('OAuth successful for user:', {
          userId: userInfo.id,
          username: userInfo.username,
          grantedScopes
        });
      } else {
        console.warn('Could not fetch user info:', userResp.status);
      }
    } catch (e) {
      console.warn('Error fetching user info:', e.message);
    }

    // Here you can store the token securely in your database if needed
    // Example: await storeUserToken(userInfo?.id, tokenData);
    
    // Success: redirect to Discord or success page (no sensitive data exposed)
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Authorization Successful</title>
        <meta charset="utf-8">
        <meta http-equiv="refresh" content="3;url=${SUCCESS_REDIRECT_URL}">
        <style>
          body { 
            font-family: Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px; 
            text-align: center;
          }
          .success { 
            background: #efe; 
            border: 1px solid #cfc; 
            padding: 30px; 
            border-radius: 5px; 
          }
          .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #5865f2;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
          }
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
          .redirect-btn { 
            background: #5865f2; 
            color: white; 
            padding: 10px 20px; 
            text-decoration: none; 
            border-radius: 3px; 
            display: inline-block; 
            margin-top: 15px;
          }
        </style>
      </head>
      <body>
        <div class="success">
          <h2>✅ Authorization Successful!</h2>
          <p>You have successfully authorized the application.</p>
          <div class="spinner"></div>
          <p>Redirecting you back to Discord...</p>
          <a href="${SUCCESS_REDIRECT_URL}" class="redirect-btn">Continue to Discord</a>
        </div>
        <script>
          // Auto-redirect after 3 seconds
          setTimeout(() => {
            window.location.href = "${SUCCESS_REDIRECT_URL}";
          }, 3000);
        </script>
      </body>
      </html>
    `);

  } catch (error) {
    console.error('Unexpected OAuth error:', error.message);
    return res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Unexpected Error</title>
        <meta charset="utf-8">
        <style>
          body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
          .error { background: #fee; border: 1px solid #fcc; padding: 20px; border-radius: 5px; }
          .retry-btn { background: #5865f2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 3px; display: inline-block; margin-top: 10px; }
        </style>
      </head>
      <body>
        <div class="error">
          <h2>💥 Unexpected Error</h2>
          <p>An unexpected error occurred during authorization. Please try again.</p>
          <a href="${buildAuthorizeUrl()}" class="retry-btn">Try Again</a>
        </div>
      </body>
      </html>
    `);
  }
}
