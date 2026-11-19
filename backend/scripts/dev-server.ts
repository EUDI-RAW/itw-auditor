import * as http from 'http';
import challenge from '../api/challenge';
import register from '../api/register';
import assert from '../api/assert';
import status from '../api/status';

/**
 * Local development server which serves the Vercel functions of `api/` on PORT (3000 by default).
 * The body is limited to 1 MB and parsed as JSON, as done by Vercel.
 */
const routes: Record<string, (req: any, res: http.ServerResponse) => Promise<void>> = {
  '/api/challenge': challenge,
  '/api/register': register,
  '/api/assert': assert,
  '/api/status': status,
};

const server = http.createServer((req, res) => {
  const route = routes[new URL(req.url ?? '/', 'http://localhost').pathname];
  if (!route) {
    res.statusCode = 404;
    res.end('{"ok":false,"error":"Not found"}');
    return;
  }
  const chunks: Buffer[] = [];
  let size = 0;
  req.on('data', (chunk: Buffer) => {
    size += chunk.length;
    if (size > 1024 * 1024) req.destroy();
    else chunks.push(chunk);
  });
  req.on('end', () => {
    const text = Buffer.concat(chunks).toString('utf-8');
    let body: unknown;
    try {
      body = text ? JSON.parse(text) : undefined;
    } catch {
      body = undefined;
    }
    Object.assign(req, { body });
    route(req, res).catch((e) => {
      console.error(e);
      res.statusCode = 500;
      res.end();
    });
  });
});

const port = Number(process.env.PORT) || 3000;
server.listen(port, () => console.log(`itwattauditor backend on http://localhost:${port}`));
