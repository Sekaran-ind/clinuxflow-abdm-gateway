// A short-lived, signed statement that this gateway looked a practitioner up in HPR and found
// them: what clinuxflow-api's doctor roster stores as "HPR verified". clinuxflow-api has no ABDM
// credentials, so without this a roster's "verified" would be whatever the browser said.
//
// Signed with JWT_SECRET (HS256), the secret this gateway and clinuxflow-api already share for
// session tokens. It deliberately carries no `sub` and no `clinicId`, the two claims a session
// token must have, so it can never pass as a session; its own `kind` is checked on the other side.
import { sign, verify } from 'hono/jwt';

export const ATTESTATION_KIND = 'hpr-attestation';
const TTL_SECONDS = 30 * 60;

/** @param {{ hprIdNumber: string, hprId?: string, name?: string, categoryId?: string }} found */
export async function attestHpr(secret, clinicId, found, now = Date.now()) {
    const iat = Math.floor(now / 1000);
    return sign({
        kind: ATTESTATION_KIND,
        clinic: clinicId,
        hprIdNumber: found.hprIdNumber,
        hprId: found.hprId || '',
        name: found.name || '',
        categoryId: found.categoryId ? String(found.categoryId) : '',
        iat,
        exp: iat + TTL_SECONDS,
    }, secret, 'HS256');
}

export async function readAttestation(secret, token) {
    const payload = await verify(token, secret, 'HS256');
    if (payload?.kind !== ATTESTATION_KIND) throw new Error('Not an HPR attestation');
    return payload;
}
