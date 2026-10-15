#!/usr/bin/env node
// fetch_google.js — download the two Google files the repo must not ship
// (copyrighted, gitignored): recaptcha__en.js and api.js, into the repo root.
// Plain Node, no npm dependencies. Usage:
//   node scripts/fetch_google.js [version] [--force]
'use strict';

const https = require('https');
const fs = require('fs');
const path = require('path');

const DEFAULT_VERSION = 'TnA7HacJFoBWt9hnlunBlYfK'; // pinned reCAPTCHA release; update when Google rotates
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36';

const argv = process.argv.slice(2);
const force = argv.includes('--force');
const version = argv.find((a) => !a.startsWith('--')) || DEFAULT_VERSION;
const root = path.resolve(__dirname, '..');

const TARGETS = [
  { url: `https://www.gstatic.com/recaptcha/releases/${version}/recaptcha__en.js`, file: 'recaptcha__en.js' },
  { url: 'https://www.google.com/recaptcha/api.js', file: 'api.js' },
];

function download(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': UA } }, (res) => {
      if (res.statusCode !== 200) {
        res.resume(); // drain so the socket is released
        return reject(new Error(`HTTP ${res.statusCode} for ${url}`));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
}

(async () => {
  let failed = false;
  for (const t of TARGETS) {
    const dest = path.join(root, t.file);
    if (fs.existsSync(dest) && !force) {
      console.log(`${t.file}: exists, skipping (delete it to re-fetch)`);
      continue;
    }
    try {
      const buf = await download(t.url);
      fs.writeFileSync(dest, buf);
      console.log(`${t.file}: wrote ${buf.length} bytes -> ${dest}`);
    } catch (e) {
      console.error(`${t.file}: FAILED: ${e.message}`);
      failed = true;
    }
  }
  process.exit(failed ? 1 : 0);
})();
