import axios from 'axios';
import crypto from 'crypto';
import 'dotenv/config';

// 1. Configure the payload (Simulating an opened PR)
const payload = {
  action: 'opened',
  repository: {
    full_name: 'Satya900/golf_project',
    owner: { login: 'Satya900' },
    name: 'golf_project'
  },
  pull_request: {
    number: 1,
    title: 'WIP: Add a buggy function for testing',
    user: { login: 'Satya900' },
    html_url: 'https://github.com/Satya900/golf_project/pull/1',
    url: 'https://api.github.com/repos/Satya900/golf_project/pulls/1'
  }
};

// 2. Mock File Patch data (What the API would return)
// In a real run, index.js fetches this from GitHub. 
// For a local mock, we'd need to mock the axios.get(pr.url + "/files") call in index.js.
// Since index.js is already running with real tokens, 
// you should use a REAL REPO in the payload below to test the full flow.

const WEBHOOK_URL = 'http://localhost:3001/webhook';
const SECRET = process.env.WEBHOOK_SECRET;

async function sendMockWebhook() {
  console.log('🚀 Sending mock PR webhook to BugLens Core...');

  const body = JSON.stringify(payload);
  const hmac = crypto.createHmac('sha256', SECRET);
  const signature = 'sha256=' + hmac.update(body).digest('hex');

  try {
    const res = await axios.post(WEBHOOK_URL, payload, {
      headers: {
        'x-github-event': 'pull_request',
        'x-hub-signature-256': signature,
        'Content-Type': 'application/json'
      }
    });
    console.log(`✅ Success! Engine responded with: ${res.status}`);
  } catch (err) {
    console.error('❌ Webhook failed:', err.response?.data || err.message);
  }
}

sendMockWebhook();
