// Per-account rate limiting for user-driven routes. Must run after requireClinuxSession(), which
// sets c.get('user').
//
// Production counts in the RATE_LIMITER Durable Object namespace (exact across isolates). When
// that binding is absent (unit tests under plain Node) an in-memory counter per env object is
// used instead; that is weaker, so the binding is configured in wrangler.toml.

const memoryWindows = new WeakMap();

function memoryHit(env, key, limit, windowMs) {
    let windows = memoryWindows.get(env);
    if (!windows) {
        windows = new Map();
        memoryWindows.set(env, windows);
    }
    const now = Date.now();
    let w = windows.get(key);
    if (!w || now - w.start >= windowMs) w = { start: now, count: 0 };
    w.count += 1;
    windows.set(key, w);
    return { allowed: w.count <= limit, remaining: Math.max(0, limit - w.count), resetAt: w.start + windowMs };
}

async function durableHit(namespace, key, limit, windowMs) {
    const stub = namespace.get(namespace.idFromName(key));
    const res = await stub.fetch('https://rate-limiter/hit', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ limit, windowMs }),
    });
    return res.json();
}

/**
 * @param {{ bucket: string, limit: number, windowSeconds: number, key?: (c) => string | Promise<string> }} options
 *   key: what to count by. Defaults to the signed-in account; citizen routes (no account) count
 *   by client IP, and OTP routes additionally by a hash of the phone/ABHA number targeted.
 */
export function rateLimit({ bucket, limit, windowSeconds, key: keyOf }) {
    const windowMs = windowSeconds * 1000;
    return async (c, next) => {
        const user = c.get('user');
        const key = `${bucket}:${keyOf ? await keyOf(c) : (user?.accountId ?? 'anonymous')}`;
        const result = c.env.RATE_LIMITER
            ? await durableHit(c.env.RATE_LIMITER, key, limit, windowMs)
            : memoryHit(c.env, key, limit, windowMs);
        if (!result.allowed) {
            const retryAfter = Math.max(1, Math.ceil((result.resetAt - Date.now()) / 1000));
            c.header('Retry-After', String(retryAfter));
            return c.json({ success: false, error: `Too many requests. Try again in ${retryAfter} seconds.` }, 429);
        }
        return next();
    };
}

/**
 * Routes that make ABDM send an OTP or verification message to a phone or email. These are
 * abuse targets (SMS pumping, harassment) and get a tight per-account limit on top of the
 * general one. Paths are relative to the gateway root.
 */
export const OTP_SENDING_PATHS = [
    '/abha/enrollment/aadhaar-otp',
    '/abha/enrollment/mobile-otp',
    '/abha/enrollment/email-verification-link',
    '/abha/login/request-otp',
    '/abha/profile/mobile/request-otp',
    '/abha/enrollment/dl/mobile-otp',
    '/abha/login/address/request-otp',
    '/hpr/registration/aadhaar-otp',
    '/hpr/registration/mobile-otp',
    '/hpr/professional/email/generate-otp',
    '/hpr/professional/email/resend-otp',
    '/hpr/password/forgot/mobile/send-otp',
    '/hpr/password/forgot/aadhaar/send-otp',
    '/hpr/hprid/forgot/aadhaar/send-otp',
    '/hpr/hprid/forgot/mobile/send-otp',
];
