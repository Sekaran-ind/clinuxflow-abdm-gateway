import { describe, expect, it } from 'vitest';
import {
    CALLBACK_OF,
    ContextSchema,
    ERROR_CODES,
    LookupRequestSchema,
    MessageSchema,
    ResponseSchema,
    SubscriberDtoSchema,
    ackResponse,
    buildCallbackContext,
    buildContext,
    extractSigningPublicKey,
    nackResponse,
} from './protocol.js';

// Real captured payloads from the NHA-ABDM/UHI Postman collection, so the schemas accept what
// the sandbox actually sends.

describe('real search request payload', () => {
    const search = {
        context: {
            domain: 'nic2004:85111',
            country: 'IND',
            city: 'std:011',
            action: 'search',
            core_version: '0.7.1',
            consumer_id: 'eua-nha',
            consumer_uri: 'https://uhieua.abdm.gov.in/api/v1/euaService',
            message_id: '1e31f690-1bdc-11ee-b6de-37f1698e0750',
            timestamp: '2023-07-06T09:04:31.649755Z',
            transaction_id: '1e31f690-1bdc-11ee-b6de-37f1698e0750',
        },
        message: {
            intent: {
                fulfillment: {
                    type: 'Online',
                    agent: { name: 'ganesh' },
                    start: { time: { timestamp: '2023-07-07T00:00:00' } },
                    end: { time: { timestamp: '2023-07-07T23:59:59' } },
                },
                item: { descriptor: { name: 'Consultation', code: 'Consultation' } },
            },
        },
    };

    it('context parses', () => {
        expect(ContextSchema.parse(search.context)).toMatchObject({ action: 'search', consumer_id: 'eua-nha' });
    });

    it('message parses', () => {
        const parsed = MessageSchema.parse(search.message);
        expect(parsed.intent?.item?.descriptor?.code).toBe('Consultation');
        expect(parsed.intent?.fulfillment?.agent?.name).toBe('ganesh');
    });
});

describe('real on_search response payload (trimmed)', () => {
    const onSearch = {
        context: {
            domain: 'nic2004:85111',
            country: 'IND',
            city: 'std:011',
            action: 'on_search',
            core_version: '0.7.1',
            consumer_id: 'eua-nha',
            consumer_uri: 'https://uhieuasandbox.abdm.gov.in/api/v1/euaService',
            provider_id: 'hspa-nha',
            message_id: '0b59c920-1bdd-11ee-b6de-37f1698e0750',
            timestamp: '2023-07-06T09:11:11.151449Z',
            provider_uri: 'https://hspasbx.abdm.gov.in/api/v1',
            transaction_id: '0b59c920-1bdd-11ee-b6de-37f1698e0750',
        },
        message: {
            catalog: {
                descriptor: { name: 'Ref HSPA', short_desc: 'ReferenceHSPA Test hospital' },
                providers: [
                    {
                        id: '1',
                        descriptor: { name: 'Test Hospital' },
                        categories: [
                            { id: '101', parent_category_id: null, descriptor: { name: 'Allopathy', code: 'ALLOPATHY' } },
                            { id: '201', parent_category_id: '101', descriptor: { name: 'Cardiology', code: 'CARDIOLOGY' } },
                        ],
                        fulfillments: [{ id: '0', type: 'Online', agent: { id: 'ganeshborse@hpr.ndhm', name: 'Ganesh Vikram Borse', image: '<base64>' } }],
                    },
                ],
            },
        },
    };

    it('context parses', () => {
        expect(ContextSchema.parse(onSearch.context).action).toBe('on_search');
    });

    it('nested providers/categories/fulfillments parse', () => {
        const provider = MessageSchema.parse(onSearch.message).catalog?.providers?.[0];
        expect(provider?.descriptor?.name).toBe('Test Hospital');
        expect(provider?.categories?.[1]?.descriptor?.code).toBe('CARDIOLOGY');
        expect(provider?.fulfillments?.[0]?.agent?.name).toBe('Ganesh Vikram Borse');
    });

    it('full envelope parses via ResponseSchema', () => {
        expect(() => ResponseSchema.parse({ message: onSearch.message })).not.toThrow();
    });

    it('unknown fields on push messages are kept, not stripped', () => {
        expect(MessageSchema.parse({ text: 'hello', order: { id: 'o1' } })).toMatchObject({ text: 'hello', order: { id: 'o1' } });
    });
});

describe('real lookup request payload', () => {
    it('parses despite `status` being absent (the spec marks it required; the real example omits it)', () => {
        const lookup = { subscriber_id: 'eua-nha', type: 'EUA', domain: 'nic2004:85111', country: 'IND', city: 'std:011', pub_key_id: 'nha.eua.k1' };
        expect(LookupRequestSchema.partial({ status: true }).parse(lookup)).toMatchObject({ subscriber_id: 'eua-nha', pub_key_id: 'nha.eua.k1' });
    });
});

describe('extractSigningPublicKey', () => {
    it('finds the key under the legacy signing_public_key field', () => {
        expect(extractSigningPublicKey(SubscriberDtoSchema.parse({ subscriber_id: 'hspa-nha', signing_public_key: 'abc123' }))).toBe('abc123');
    });
    it('returns undefined when no known field is present', () => {
        expect(extractSigningPublicKey(SubscriberDtoSchema.parse({ subscriber_id: 'hspa-nha' }))).toBeUndefined();
    });
});

describe('buildContext / buildCallbackContext', () => {
    const base = { domain: 'nic2004:85111', city: 'std:011', country: 'IND', consumerId: 'eua.example', consumerUri: 'https://eua.example/uhi/eua' };

    it('generates a fresh transaction_id when none is given', () => {
        const ctx = buildContext({ ...base, action: 'search' });
        expect(ctx.transaction_id).toBeTruthy();
        expect(ctx.message_id).toBeTruthy();
    });

    it('reuses a given transaction_id', () => {
        expect(buildContext({ ...base, action: 'init', transactionId: 'fixed' }).transaction_id).toBe('fixed');
    });

    it('callback context keeps the transaction and swaps the action', () => {
        const request = buildContext({ ...base, action: 'init' });
        const callback = buildCallbackContext(request, CALLBACK_OF.init);
        expect(callback.action).toBe('on_init');
        expect(callback.transaction_id).toBe(request.transaction_id);
        expect(callback.message_id).not.toBe(request.message_id);
    });
});

describe('ack/nack helpers', () => {
    it('ackResponse', () => {
        expect(ackResponse()).toEqual({ message: { ack: { status: 'ACK' } } });
    });
    it('nackResponse carries the error', () => {
        expect(nackResponse({ code: ERROR_CODES.UNAUTHORISED, message: 'INVALID SIGNATURE' })).toEqual({
            message: { ack: { status: 'NACK' } },
            error: { code: 'UHI-1405', message: 'INVALID SIGNATURE' },
        });
    });
});
