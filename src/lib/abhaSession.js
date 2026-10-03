// Calls made with a person's own ABHA session (the X-token ABDM hands out after an ABHA login or
// enrolment): profile and ABHA card. Shared by the citizen routes (cubo-diary) and the clinic's
// staff routes (routes/abha.js).
//
// Two kinds of ABHA session: signing in with an ABHA number gives an ABHA token ("abha": profile
// and card under /profile/account); signing in with an ABHA address gives a PHR token ("phr":
// profile and card under /phr/web/login/profile).
import { AbdmApiError } from './abdmClient.js';
import { getAbdmConfig } from './config.js';
import { getAccessToken } from './sessionToken.js';

/** Raw GET against ABHA with the user's token, for endpoints that return JSON or a file. */
export async function abhaGet(env, paths, { token }) {
    const config = getAbdmConfig(env);
    const accessToken = await getAccessToken(env);
    let last;
    // The sandbox PHR paths are given without hyphens in NHA's PDF (a text-extraction artefact:
    // production uses phr-card / abha-profile); the first that isn't 404 wins.
    for (const path of paths) {
        const res = await fetch(`${config.abhaBaseUrl}${path}`, {
            headers: { 'REQUEST-ID': crypto.randomUUID(), TIMESTAMP: new Date().toISOString(), 'X-CM-ID': config.xCmId, Authorization: `Bearer ${accessToken}`, 'X-token': `Bearer ${token}` },
        });
        if (res.status === 404 && path !== paths.at(-1)) {
            last = res;
            continue;
        }
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            let body;
            try {
                body = JSON.parse(text);
            } catch {
                body = text.slice(0, 300);
            }
            throw new AbdmApiError(res.status, body);
        }
        return res;
    }
    throw new AbdmApiError(last?.status ?? 404, 'not found');
}

export const PROFILE_PATHS = { abha: ['/profile/account'], phr: ['/phr/web/login/profile/abha-profile', '/phr/web/login/profile/abhaprofile'] };
export const CARD_PATHS = { abha: ['/profile/account/abha-card'], phr: ['/phr/web/login/profile/abha/phr-card', '/phr/web/login/profile/abha/phrcard'] };

/** The ABHA profile, normalised across the two token kinds. */
export async function fetchProfile(env, s) {
    const p = await (await abhaGet(env, PROFILE_PATHS[s.kind], s)).json();
    return {
        abhaNumber: p.ABHANumber ?? p.abhaNumber ?? p.healthIdNumber,
        abhaAddress: p.preferredAbhaAddress ?? p.abhaAddress ?? p.healthId,
        name: p.name ?? p.fullName ?? [p.firstName, p.middleName, p.lastName].filter(Boolean).join(' '),
        firstName: p.firstName,
        middleName: p.middleName,
        lastName: p.lastName,
        gender: p.gender,
        dayOfBirth: p.dayOfBirth,
        monthOfBirth: p.monthOfBirth,
        yearOfBirth: p.yearOfBirth,
        districtName: p.districtName,
        stateName: p.stateName,
        mobile: p.mobile,
        kycVerified: p.kycVerified ?? (p.kycStatus ? p.kycStatus === 'VERIFIED' : undefined),
        photo: p.profilePhoto ?? null,
    };
}

/** The ABHA card (ABDM answers with a PNG or a PDF) as { contentType, data: base64 }. */
export async function fetchCard(env, s) {
    const res = await abhaGet(env, CARD_PATHS[s.kind], s);
    const contentType = (res.headers.get('content-type') || 'application/octet-stream').split(';')[0].trim();
    const bytes = new Uint8Array(await res.arrayBuffer());
    if (!bytes.length) throw new AbdmApiError(502, 'ABDM returned an empty ABHA card');
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return { contentType, data: btoa(bin) };
}
