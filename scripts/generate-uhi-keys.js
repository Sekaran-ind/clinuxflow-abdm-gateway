// Generates an Ed25519 key pair for a UHI role (HSPA or EUA).
//
//   npm run uhi:generate-keys -- hspa
//
// Prints the private key for `wrangler secret put UHI_<ROLE>_PRIVATE_KEY_DER` (or .dev.vars) and
// the public key to register with the UHI network registry for that subscriber id.
import { generateKeyPair } from '../src/uhi/crypto.js';

const role = (process.argv[2] || '').toUpperCase();
if (role !== 'HSPA' && role !== 'EUA') {
    console.error('Usage: npm run uhi:generate-keys -- <hspa|eua>');
    process.exit(1);
}
const { publicKeyDer, privateKeyDer } = generateKeyPair();
console.log(`UHI_${role}_PRIVATE_KEY_DER=${privateKeyDer}`);
console.log(`# public key (base64 SPKI DER) to register for this subscriber:`);
console.log(`# ${publicKeyDer}`);
