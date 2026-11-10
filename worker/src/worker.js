export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Target Backend Host configured via wrangler.toml [vars]
    const targetHost = env.BACKEND_HOST;
    if (!targetHost) {
      return new Response(
        JSON.stringify({ error: 'BACKEND_HOST environment variable is not configured' }),
        { status: 500, headers: { 'Content-Type': 'application/json' } }
      );
    }

    const targetUrl = new URL(url.pathname + url.search, `https://${targetHost}`);

    // Create fresh request headers without the client's Host header to prevent 1003/loop
    const newHeaders = new Headers();
    for (const [key, val] of request.headers.entries()) {
      const lower = key.toLowerCase();
      if (['host', 'cf-ray', 'cf-connecting-ip', 'cf-visitor', 'cf-ipcountry', 'x-forwarded-proto'].includes(lower)) {
        continue;
      }
      newHeaders.set(key, val);
    }

    newHeaders.set('Host', targetHost);
    newHeaders.set('X-Forwarded-Host', url.hostname);
    newHeaders.set('X-Forwarded-Proto', 'https');

    const clientIp = request.headers.get('CF-Connecting-IP');
    if (clientIp) {
      newHeaders.set('X-Real-IP', clientIp);
      newHeaders.set('X-Forwarded-For', clientIp);
      newHeaders.set('CF-Connecting-IP', clientIp);
    }

    // Handle WebSocket upgrade for in-VM console
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
      return fetch(targetUrl.toString(), {
        method: request.method,
        headers: newHeaders,
        body: request.body
      });
    }

    try {
      const response = await fetch(targetUrl.toString(), {
        method: request.method,
        headers: newHeaders,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'manual'
      });

      const resHeaders = new Headers(response.headers);
      resHeaders.set('X-Edge-Server', 'Cloudflare-Worker-BF');

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: resHeaders
      });
    } catch (err) {
      return new Response(
        JSON.stringify({
          error: 'Gateway Connection Failed',
          message: err.message
        }),
        {
          status: 502,
          headers: { 'Content-Type': 'application/json' }
        }
      );
    }
  }
};
