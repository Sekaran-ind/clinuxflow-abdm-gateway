// UHI v2.0.2 protocol envelope: zod schemas, action lists, context builders, ack/nack.
//
// Ported from clinux-uhi-gateway's packages/uhi-protocol. Field lists follow the live sandbox's
// own OpenAPI (https://uhigatewaysandbox.abdm.gov.in/swagger-docs/v2.0.2/Gateway.yaml), not the
// older core.yml in the NHA-ABDM/UHI repo. Almost everything in the protocol is optional by
// design (domain extension via free-form `tags`), so these schemas are deliberately permissive.

import { z } from 'zod';

// --- actions ---------------------------------------------------------------------------------

/** Authoritative action list from the sandbox's paths (the spec's own Context.action enum is
 * stale and misses cancel/on_cancel/on_update/on_message). */
export const HSPA_INBOUND_ACTIONS = ['search', 'select', 'init', 'confirm', 'status', 'cancel'];
export const EUA_INBOUND_ACTIONS = ['on_search', 'on_select', 'on_init', 'on_confirm', 'on_status', 'on_cancel'];
/** Pushed unsolicited by either side. */
export const PUSH_ACTIONS = ['on_update', 'on_message'];
export const ALL_ACTIONS = [...HSPA_INBOUND_ACTIONS, ...EUA_INBOUND_ACTIONS, ...PUSH_ACTIONS];

export const CALLBACK_OF = {
    search: 'on_search',
    select: 'on_select',
    init: 'on_init',
    confirm: 'on_confirm',
    status: 'on_status',
    cancel: 'on_cancel',
};

// --- common ----------------------------------------------------------------------------------

export const TagsSchema = z.record(z.string(), z.string());

export const DescriptorSchema = z.object({
    name: z.string().optional(),
    code: z.string().optional(),
    symbol: z.string().optional(),
    short_desc: z.string().optional(),
    long_desc: z.string().optional(),
    images: z.array(z.string()).optional(),
    audio: z.string().optional(),
    '3d_render': z.string().optional(),
});

const ScheduleSchema = z.object({
    frequency: z.string().optional(),
    holidays: z.array(z.string()).optional(),
    times: z.array(z.string()).optional(),
});

/** UHI uses ISO 8601 without a timezone, e.g. "2022-07-15T00:00:00". */
export const TimeSchema = z.object({
    label: z.string().optional(),
    timestamp: z.string().optional(),
    duration: z.string().optional(),
    range: z.object({ start: z.string().optional(), end: z.string().optional() }).optional(),
    days: z.string().optional(),
    schedule: ScheduleSchema.optional(),
});

const DecimalValueSchema = z.string().regex(/^[+-]?([0-9]*[.])?[0-9]+$/);

export const PriceSchema = z.object({
    currency: z.string().optional(),
    value: DecimalValueSchema.optional(),
    estimated_value: DecimalValueSchema.optional(),
    computed_value: DecimalValueSchema.optional(),
    listed_value: DecimalValueSchema.optional(),
    offered_value: DecimalValueSchema.optional(),
    minimum_value: DecimalValueSchema.optional(),
    maximum_value: DecimalValueSchema.optional(),
});

export const ContactSchema = z.object({
    phone: z.string().optional(),
    email: z.string().optional(),
    tags: TagsSchema.optional(),
});

export const PersonSchema = z.object({
    id: z.string().optional(),
    name: z.string(),
    image: z.string().optional(),
    dob: z.string().optional(),
    gender: z.string().optional(),
    cred: z.string().optional(),
    tags: TagsSchema.optional(),
});

/** An order executor: Person and Contact fields flattened together. */
export const AgentSchema = PersonSchema.partial({ name: true }).merge(ContactSchema);

const AddressSchema = z.object({
    door: z.string().optional(),
    name: z.string().optional(),
    building: z.string().optional(),
    street: z.string().optional(),
    locality: z.string().optional(),
    ward: z.string().optional(),
    city: z.string().optional(),
    state: z.string().optional(),
    country: z.string().optional(),
    area_code: z.string().optional(),
});

const OrganizationSchema = z.object({ name: z.string().optional(), cred: z.string().optional() });

const StateSchema = z.object({
    descriptor: DescriptorSchema.optional(),
    updated_at: z.string().optional(),
    updated_by: z.string().optional(),
});

// --- catalog ---------------------------------------------------------------------------------

export const CategorySchema = z.object({
    id: z.string().optional(),
    // real payloads send `null` (not just absent) for top-level categories
    parent_category_id: z.string().nullable().optional(),
    descriptor: DescriptorSchema.optional(),
    time: TimeSchema.optional(),
    tags: TagsSchema.optional(),
});

export const ItemSchema = z.object({
    id: z.string().optional(),
    parent_item_id: z.string().optional(),
    descriptor: DescriptorSchema.optional(),
    price: PriceSchema.optional(),
    category_id: z.string().optional(),
    fulfillment_id: z.string().optional(),
    time: TimeSchema.optional(),
    matched: z.boolean().optional(),
    related: z.boolean().optional(),
    recommended: z.boolean().optional(),
    tags: TagsSchema.optional(),
});

const FulfillmentEndpointSchema = z.object({
    time: TimeSchema.optional(),
    instructions: DescriptorSchema.optional(),
    contact: ContactSchema.optional(),
    person: PersonSchema.optional(),
});

export const FulfillmentSchema = z.object({
    id: z.string().optional(),
    type: z.string().optional(),
    provider_id: z.string().optional(),
    state: StateSchema.optional(),
    tracking: z.boolean().default(false).optional(),
    customer: z.object({ person: PersonSchema.optional(), contact: ContactSchema.optional() }).optional(),
    agent: AgentSchema.optional(),
    person: PersonSchema.optional(),
    contact: ContactSchema.optional(),
    start: FulfillmentEndpointSchema.optional(),
    end: FulfillmentEndpointSchema.optional(),
    tags: TagsSchema.optional(),
});

export const PaymentSchema = z.object({
    uri: z.string().optional(),
    tl_method: z.enum(['https', 'payto']).optional(),
    params: z
        .object({
            transaction_id: z.string().optional(),
            transaction_status: z.string().optional(),
            amount: z.string().optional(),
            currency: z.string().optional(),
        })
        .catchall(z.string())
        .optional(),
    type: z.enum(['ON-ORDER', 'PRE-FULFILLMENT', 'ON-FULFILLMENT', 'POST-FULFILLMENT']).optional(),
    status: z.enum(['PAID', 'NOT-PAID']).optional(),
    time: TimeSchema.optional(),
});

const QuotationSchema = z.object({
    price: PriceSchema.optional(),
    breakup: z.array(z.object({ title: z.string().optional(), price: PriceSchema.optional() })).optional(),
    ttl: z.string().optional(),
});

const BillingSchema = z.object({
    name: z.string(),
    organization: OrganizationSchema.optional(),
    address: AddressSchema.optional(),
    email: z.string().email().optional(),
    phone: z.string(),
    time: TimeSchema.optional(),
    tax_number: z.string().optional(),
    created_at: z.string().optional(),
    updated_at: z.string().optional(),
});

const CustomerSchema = z.object({
    person: z
        .object({
            gender: z.string().optional(),
            dob: z.string().optional(),
            dayOfBirth: z.number().int().optional(),
            monthOfBirth: z.number().int().optional(),
            yearOfBirth: z.number().int().optional(),
        })
        .optional(),
    id: z.string().optional(),
    cred: z.string().optional(),
    Contact: ContactSchema.optional(),
});

export const ProviderSchema = z.object({
    id: z.string().optional(),
    descriptor: DescriptorSchema.optional(),
    category_id: z.string().optional(),
    time: TimeSchema.optional(),
    categories: z.array(CategorySchema).optional(),
    fulfillments: z.array(FulfillmentSchema).optional(),
    payments: z.array(PaymentSchema).optional(),
    items: z.array(ItemSchema).optional(),
    exp: z.string().optional(),
    tags: TagsSchema.optional(),
});

export const CatalogSchema = z.object({
    descriptor: DescriptorSchema.optional(),
    categories: z.array(CategorySchema).optional(),
    fulfillments: z.array(FulfillmentSchema).optional(),
    payments: z.array(PaymentSchema).optional(),
    providers: z.array(ProviderSchema).optional(),
    exp: z.string().optional(),
});

// --- order / intent --------------------------------------------------------------------------

export const IntentSchema = z.object({
    descriptor: DescriptorSchema.optional(),
    provider: ProviderSchema.optional(),
    fulfillment: FulfillmentSchema.optional(),
    payment: PaymentSchema.optional(),
    category: z.object({ descriptor: DescriptorSchema.optional() }).optional(),
    item: ItemSchema.optional(),
    tags: TagsSchema.optional(),
});

export const OrderSchema = z.object({
    id: z.string().optional(),
    state: z.string().optional(),
    provider: z.object({ id: z.string().optional() }).optional(),
    item: ItemSchema.optional(),
    billing: BillingSchema.optional(),
    fulfillment: FulfillmentSchema.optional(),
    quote: QuotationSchema.optional(),
    payment: PaymentSchema.optional(),
    created_at: z.string().optional(),
    updated_at: z.string().optional(),
    customer: CustomerSchema.optional(),
});

// --- context ---------------------------------------------------------------------------------

export const ContextSchema = z.object({
    domain: z.string(),
    country: z.string(),
    city: z.string(),
    action: z.enum(ALL_ACTIONS),
    core_version: z.string(),
    consumer_id: z.string(),
    consumer_uri: z.string(),
    provider_id: z.string().optional(),
    provider_uri: z.string().optional(),
    transaction_id: z.string(),
    message_id: z.string(),
    timestamp: z.string(),
    key: z.string().optional(),
    ttl: z.string().optional(),
});

/** Message-format version the captured real examples use (distinct from protocol v2.0.2). */
export const CORE_VERSION = '0.7.1';

export function buildContext(params) {
    return {
        domain: params.domain,
        country: params.country,
        city: params.city,
        action: params.action,
        core_version: params.coreVersion ?? CORE_VERSION,
        consumer_id: params.consumerId,
        consumer_uri: params.consumerUri,
        provider_id: params.providerId,
        provider_uri: params.providerUri,
        transaction_id: params.transactionId ?? crypto.randomUUID(),
        message_id: crypto.randomUUID(),
        timestamp: new Date().toISOString(),
        ttl: params.ttlSeconds !== undefined ? `PT${params.ttlSeconds}S` : undefined,
    };
}

/** Context for an on_* callback: same transaction and consumer/provider pair, action swapped. */
export function buildCallbackContext(requestContext, callbackAction) {
    return { ...requestContext, action: callbackAction, message_id: crypto.randomUUID(), timestamp: new Date().toISOString() };
}

// --- envelope --------------------------------------------------------------------------------

export const AckSchema = z.object({ ack: z.object({ status: z.enum(['ACK', 'NACK']) }) });

export const ErrorSchema = z.object({
    type: z.string().optional(),
    code: z.string(),
    path: z.string().optional(),
    message: z.string().optional(),
});

/**
 * message.{intent|order|catalog|ack}.
 *
 * KNOWN SPEC GAP: the sandbox spec confirms on_update and on_message exist but doesn't document
 * their `message` shape. `.passthrough()` keeps whatever either side sends rather than silently
 * stripping it.
 */
export const MessageSchema = z
    .object({
        intent: IntentSchema.optional(),
        order: OrderSchema.optional(),
        catalog: CatalogSchema.optional(),
        ack: AckSchema.shape.ack.optional(),
    })
    .passthrough();

export const ResponseSchema = z.object({ message: MessageSchema.optional(), error: ErrorSchema.optional() });

export function ackResponse() {
    return { message: { ack: { status: 'ACK' } } };
}

export function nackResponse(error) {
    return { message: { ack: { status: 'NACK' } }, error };
}

/**
 * UNAUTHORISED (UHI-1405) is confirmed by the signing PDF. The other two are this
 * implementation's own placeholders for business failures, not confirmed official codes.
 */
export const ERROR_CODES = {
    UNAUTHORISED: 'UHI-1405',
    ITEM_NOT_FOUND: 'UHI-REF-ITEM-NOT-FOUND',
    ORDER_NOT_FOUND: 'UHI-REF-ORDER-NOT-FOUND',
};

// --- network registry ------------------------------------------------------------------------

/** Body for POST /api/v1/networkregistry/lookup (flat, no context wrapper). */
export const LookupRequestSchema = z.object({
    subscriber_id: z.string().optional(),
    type: z.string().optional(),
    domain: z.string(),
    country: z.string().length(3),
    city: z.string(),
    status: z.enum(['INITIATED', 'SUBSCRIBED', 'UNSUBSCRIBED']),
    pub_key_id: z.string(),
});

/**
 * KNOWN SPEC GAP: the sandbox's SubscriberDto (v2.0.2) has no documented field for the Ed25519
 * signing key; the legacy core.yml called it `signing_public_key`. Not confirmable without
 * registered sandbox credentials, so `.passthrough()` keeps unknown fields and
 * SIGNING_PUBLIC_KEY_FIELD_CANDIDATES tries the plausible names.
 */
export const SubscriberDtoSchema = z
    .object({
        city: z.string().optional(),
        country: z.string().optional(),
        domain: z.string().optional(),
        encr_public_key: z.string().optional(),
        participant_id: z.string().optional(),
        pub_key_id: z.string().optional(),
        status: z.enum(['INITIATED', 'SUBSCRIBED', 'UNSUBSCRIBED']).optional(),
        subscriber_id: z.string().optional(),
        subscriber_url: z.string().optional(),
        type: z.enum(['consumer', 'provider', 'gateway']).optional(),
        signing_public_key: z.string().optional(),
        valid_from: z.string().optional(),
        valid_until: z.string().optional(),
    })
    .passthrough();

export const SIGNING_PUBLIC_KEY_FIELD_CANDIDATES = ['signing_public_key', 'signingPublicKey', 'public_key'];

export function extractSigningPublicKey(subscriber) {
    for (const field of SIGNING_PUBLIC_KEY_FIELD_CANDIDATES) {
        const value = subscriber?.[field];
        if (typeof value === 'string' && value.length > 0) return value;
    }
    return undefined;
}
