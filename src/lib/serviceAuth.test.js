import { describe, it, expect } from 'vitest';
import { Hono } from 'hono';
import { serviceKeyAuth } from './serviceAuth.js';

function buildApp() {
    const app = new Hono();
    app.use('*', serviceKeyAuth({ exemptPaths: ['/health'] }));
    app.get('/health', (c) => c.text('ok'));
    app.get('/protected', (c) => c.text('secret'));
    return app;
}

describe('serviceKeyAuth', () => {
    it('allows exempt paths through with no key at all', async () => {
        const res = await buildApp().request('/health', {}, { SERVICE_KEY: 'right-key' });
        expect(res.status).toBe(200);
    });

    it('rejects a protected path with no key header', async () => {
        const res = await buildApp().request('/protected', {}, { SERVICE_KEY: 'right-key' });
        expect(res.status).toBe(401);
    });

    it('rejects a protected path with the wrong key', async () => {
        const res = await buildApp().request(
            '/protected',
            { headers: { 'X-Service-Key': 'wrong-key' } },
            { SERVICE_KEY: 'right-key' }
        );
        expect(res.status).toBe(401);
    });

    it('allows a protected path through with the correct key', async () => {
        const res = await buildApp().request(
            '/protected',
            { headers: { 'X-Service-Key': 'right-key' } },
            { SERVICE_KEY: 'right-key' }
        );
        expect(res.status).toBe(200);
        expect(await res.text()).toBe('secret');
    });

    // Fails closed: an unset/empty SERVICE_KEY must never be treated as "auth disabled", even
    // if a caller happens to send a matching empty string.
    it('rejects everything when SERVICE_KEY is not configured, even a matching empty key', async () => {
        const res = await buildApp().request(
            '/protected',
            { headers: { 'X-Service-Key': '' } },
            { SERVICE_KEY: '' }
        );
        expect(res.status).toBe(401);
    });
});
