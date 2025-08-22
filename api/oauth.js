import axios from 'axios';
import qs from 'qs';

const API_ENDPOINT = 'https://discord.com/api/v10';
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

export default async function handler(req, res) {
  const code = req.query.code;

  if (!code) {
    return res.status(400).json({ error: 'Missing code' });
  }

  try {
    const data = qs.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI
    });

    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    };

    const response = await axios.post(`${API_ENDPOINT}/oauth2/token`, data, {
      headers,
      auth: {
        username: CLIENT_ID,
        password: CLIENT_SECRET
      }
    });

    return res.status(200).json(response.data);
  } catch (error) {
    console.error(error.response?.data || error.message);
    return res.status(500).json({ error: 'Error exchanging code for token' });
  }
}
