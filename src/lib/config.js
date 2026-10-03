// Central place that resolves ABDM environment config from Worker bindings (env). Nothing here
// should be hardcoded elsewhere in the codebase — switching sandbox -> production should be a
// wrangler.toml [vars] + secrets change only, never a code change.

/**
 * @param {object} env - Worker environment bindings.
 * @returns {{
 *   environment: string,
 *   gatewayBaseUrl: string,
 *   hprHfrBaseUrl: string,
 *   abhaBaseUrl: string,
 *   xCmId: string,
 *   phrBaseUrl: string,
 *   hiecmBaseUrl: string,
 *   facilityBridgeBaseUrl: string,
 *   publicBaseUrl: string,
 *   clientId: string,
 *   clientSecret: string,
 * }}
 */
export function getAbdmConfig(env) {
    const clientId = env.ABDM_CLIENT_ID;
    const clientSecret = env.ABDM_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
        throw new ConfigError(
            'ABDM_CLIENT_ID / ABDM_CLIENT_SECRET are not set. For local dev, copy .dev.vars.example ' +
            'to .dev.vars and fill them in. In deployed environments, set them with `wrangler secret put`.'
        );
    }

    return {
        environment: env.ABDM_ENV || 'sandbox',
        gatewayBaseUrl: env.ABDM_GATEWAY_BASE_URL || 'https://dev.abdm.gov.in/api/hiecm/gateway/v3',
        hprHfrBaseUrl: env.ABDM_HPR_HFR_BASE_URL || 'https://apihspsbx.abdm.gov.in/v4/int',
        // Note this already includes the /abha/api/v3 path segment ABHA's own doc calls
        // "{{base_url}}" — HPR/HFR's hprHfrBaseUrl does NOT include an equivalent version
        // segment, so don't assume the two base URLs compose the same way when adding routes.
        abhaBaseUrl: env.ABDM_ABHA_BASE_URL || 'https://abhasbx.abdm.gov.in/abha/api/v3',
        xCmId: env.ABDM_X_CM_ID || 'sbx',
        // The PHR web app a patient's phone opens: face-auth QR codes (ABHA V3 doc §6.2.2) and a
        // facility's Scan & Share QR (Scan & Share doc §4.1) point here.
        phrBaseUrl: env.ABDM_PHR_BASE_URL || 'https://phrsbx.abdm.gov.in',
        // HIE-CM, for Scan & Share's on-share acknowledgement (/patient-share/v3/on-share) and
        // ABDM's signing keys (/gateway/v3/certs).
        hiecmBaseUrl: env.ABDM_HIECM_BASE_URL || 'https://dev.abdm.gov.in/api/hiecm',
        // HFR's bridge service linkage (Scan & Share doc §3.2.5, option 2).
        facilityBridgeBaseUrl: env.ABDM_FACILITY_BRIDGE_BASE_URL || 'https://facilitysbx.abdm.gov.in',
        // This gateway's own public origin (= the bridge URL ABDM calls back): the Scan & Pay
        // page patients open, and the data push URL this gateway gives HIPs as a HIU. Empty means
        // "the origin the request came in on", which is right behind the bridge URL.
        publicBaseUrl: String(env.ABDM_PUBLIC_BASE_URL || env.UHI_PUBLIC_BASE_URL || '').replace(/\/$/, ''),
        clientId,
        clientSecret,
    };
}

export class ConfigError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ConfigError';
    }
}
