// The OTP a HIP sends when a patient asks, from their ABHA app, to link records found at the
// facility (M2 user-initiated linking: on-init says authenticationType MEDIATE, medium MOBILE;
// the patient types the OTP into the app and ABDM forwards it in link/care-context/confirm).
//
// ABDM leaves delivery to the HIP. With SMS_WEBHOOK_URL set, the OTP is POSTed there as
// { to, message } (bridge it to any SMS provider). Without one, in the ABDM sandbox only, the OTP
// is kept for the clinic's staff to read out (GET /hie/hip/link-requests), labelled as such; in
// production linking is refused instead, because an OTP nobody receives proves nothing.

const OTP_TTL_MS = 10 * 60 * 1000;
export const MAX_OTP_ATTEMPTS = 3;

export const newOtp = () => String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, '0');

export async function otpHash(transactionId, otp) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${transactionId}:${String(otp).trim()}`));
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

export const otpExpiry = (now = Date.now()) => new Date(now + OTP_TTL_MS).toISOString();

/**
 * @returns {Promise<{ delivery: 'sms' | 'sandbox' }>}
 * @throws when there is no way to deliver it (production without an SMS provider) or the provider fails.
 */
export async function deliverOtp(env, { mobile, otp, facilityName }) {
    const message = `${otp} is your OTP to link your health records at ${facilityName || 'the facility'} with your ABHA. It is valid for 10 minutes. Do not share it.`;
    if (env.SMS_WEBHOOK_URL) {
        const res = await fetch(env.SMS_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...(env.SMS_WEBHOOK_TOKEN ? { Authorization: `Bearer ${env.SMS_WEBHOOK_TOKEN}` } : {}) },
            body: JSON.stringify({ to: mobile, message }),
        });
        if (!res.ok) throw new Error(`The SMS provider answered ${res.status}`);
        return { delivery: 'sms' };
    }
    if ((env.ABDM_ENV || 'sandbox') === 'sandbox') return { delivery: 'sandbox' };
    throw new Error('This facility cannot send an OTP right now');
}
