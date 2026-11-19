import type { IncomingMessage, ServerResponse } from 'http';
import type { JsonResponse } from './service';

type Request = IncomingMessage & { body?: unknown };

/**
 * Wraps a service endpoint as a Node.js / Vercel function handler: it checks the HTTP method, passes the
 * JSON body (already parsed by Vercel, or by the development server) and serializes the response.
 * @param method - The allowed HTTP method.
 * @param endpoint - The service endpoint.
 * @returns the handler.
 */
export const handler =
  (method: 'GET' | 'POST', endpoint: (body: unknown) => Promise<JsonResponse>) =>
  async (req: Request, res: ServerResponse) => {
    let response: JsonResponse;
    if (req.method !== method) {
      response = { status: 405, body: { ok: false, error: `Use ${method}` } };
    } else {
      try {
        response = await endpoint(req.body);
      } catch (e) {
        console.error(e);
        response = {
          status: 500,
          body: { ok: false, error: e instanceof Error ? e.message : `${e}` },
        };
      }
    }
    res.statusCode = response.status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify(response.body, null, 2));
  };
