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
