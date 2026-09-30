// ClinuxFlow user-session gate for every route a ClinuxFlow user drives (the ABDM /hpr, /hfr,
// /abha routes and the UHI operator routes).
//
// Why: before this, the gateway's only check was X-Service-Key, whose value is compiled into
// the public frontend bundle, so anyone who read the bundle could drive OTP-sending ABDM
// endpoints (finding S3, docs SPEC-01 §10). The frontend's apiFetch() already sends the
// clinuxflow-api session as `Authorization: Bearer <jwt>`; this verifies it with the same
// HS256 secret clinuxflow-api signs with (JWT_SECRET, set on both Workers).
//
// Limits, stated plainly: this checks signature and expiry only. It cannot see account status
// in clinuxflow-api's D1, so a disabled account's token keeps working here until it expires,
// the same gap requireUser() has in clinuxflow-api (finding S4).
//
// ABDM's own per-user tokens never use the Authorization header on the way in (HFR uses
// X-HPRID-Auth-Token, ABHA uses X-ABHA-Token, HPR passes hprToken in the body), so there is no
// collision with the session bearer token.

import { verify } from 'hono/jwt';

export function requireClinuxSession() {
    return async (c, next) => {
        if (!c.env.JWT_SECRET) {
            // Fail closed: a missing secret must never mean "auth disabled".
            console.error('[clinuxflow-abdm-gateway] JWT_SECRET is not configured; rejecting user-driven request');
            return c.json({ success: false, error: 'Gateway authentication is not configured' }, 503);
        }
        const header = c.req.header('Authorization') || '';
        const match = header.match(/^Bearer\s+(.+)$/i);
        if (!match) return c.json({ success: false, error: 'Sign in required' }, 401);

        let payload;
        try {
            payload = await verify(match[1], c.env.JWT_SECRET, 'HS256');
        } catch {
            return c.json({ success: false, error: 'Session is invalid or expired' }, 401);
        }
        if (!payload?.sub || !payload?.clinicId) {
            return c.json({ success: false, error: 'Session is invalid or expired' }, 401);
        }
        c.set('user', { accountId: payload.sub, clinicId: payload.clinicId });
        return next();
    };
}
