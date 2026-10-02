// Fixed-window rate limiter, one Durable Object instance per `${bucket}:${accountId}` key (see
// src/lib/rateLimit.js). A single instance per key gives an exact count across every isolate,
// which an in-memory counter can't.

export class RateLimiter {
    constructor(state, env) {
        this.state = state;
        this.env = env;
    }

    async fetch(request) {
        const url = new URL(request.url);
        if (url.pathname !== '/hit' || request.method !== 'POST') return new Response('Not found', { status: 404 });

        const { limit, windowMs } = await request.json();
        const now = Date.now();
        let window = (await this.state.storage.get('window')) || { start: now, count: 0 };
        if (now - window.start >= windowMs) window = { start: now, count: 0 };
        window.count += 1;
        await this.state.storage.put('window', window);
        await this.state.storage.setAlarm(window.start + windowMs * 2);

        const resetAt = window.start + windowMs;
        return Response.json({ allowed: window.count <= limit, remaining: Math.max(0, limit - window.count), resetAt });
    }

    async alarm() {
        await this.state.storage.deleteAll();
    }
}
