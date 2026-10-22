import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.zip': 'application/zip',
  '.ico': 'image/x-icon'
};

const server = http.createServer((req, res) => {
  const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let reqPath = urlObj.pathname;

  // 1. Root redirect: always redirect to /dashboard/dashboard.html with 302
  if (reqPath === '/' || reqPath === '') {
    res.writeHead(302, { 
      'Location': '/dashboard/dashboard.html',
      'Cache-Control': 'no-cache'
    });
    res.end();
    return;
  }

  // 2. Resolve safe path
  const rawPath = path.normalize(reqPath).replace(/^(\.\.[\/\\])+/, '');
  let filePath = path.join(ROOT, rawPath);

  // Security check: ensure path stays within ROOT
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('403 Forbidden');
    return;
  }

  // 3. Fallback resolution: if file doesn't exist at root, check inside dashboard/
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    const dashboardSubPath = path.join(ROOT, 'dashboard', path.basename(rawPath));
    if (fs.existsSync(dashboardSubPath) && fs.statSync(dashboardSubPath).isFile()) {
      filePath = dashboardSubPath;
    }
  }

  // 4. Check if file exists
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    console.warn(`[404 Not Found]: ${req.method} ${req.url} -> ${filePath}`);
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`404 Not Found: ${reqPath}`);
    return;
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  res.writeHead(200, {
    'Content-Type': contentType,
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-cache, no-store, must-revalidate'
  });

  const stream = fs.createReadStream(filePath);
  stream.pipe(res);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n======================================================`);
  console.log(`🛡️  ExtensionLedger Security Intelligence Server`);
  console.log(`   Running at: http://localhost:${PORT}/dashboard/dashboard.html`);
  console.log(`   Redirect from root / -> /dashboard/dashboard.html active`);
  console.log(`======================================================\n`);
});
