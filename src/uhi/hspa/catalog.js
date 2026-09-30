// HSPA provider catalog.
//
// The catalog served on `on_search` is read from the UHI record store (key `hspa-catalog`),
// published by an operator via PUT /uhi/hspa/internal/catalog. Until one is published, the
// fixture below is served: it matches the shape of a real captured on_search from the
// NHA-ABDM/UHI Postman collection. Deriving the catalog automatically from the facility's
// ClinuxFlow data (HFR facility, HPR doctors, services, hours) is a planned follow-up.

import { CatalogSchema } from '../protocol.js';

export const CATALOG_KEY = 'hspa-catalog';

export const FIXTURE_CATALOG = {
    descriptor: { name: 'Reference HSPA', short_desc: 'Reference HSPA fixture catalog' },
    providers: [
        {
            id: 'hspa-local-provider-1',
            descriptor: { name: 'Reference Test Hospital', short_desc: 'Reference HSPA fixture hospital' },
            categories: [
                { id: 'allopathy', parent_category_id: null, descriptor: { name: 'Allopathy', code: 'ALLOPATHY' } },
                { id: 'cardiology', parent_category_id: 'allopathy', descriptor: { name: 'Cardiology', code: 'CARDIOLOGY' } },
                { id: 'dermatology', parent_category_id: 'allopathy', descriptor: { name: 'Dermatology', code: 'DERMATOLOGY' } },
            ],
            fulfillments: [{ id: 'online', type: 'Online', agent: { name: 'Dr. Reference Doctor' } }],
            items: [
                {
                    id: 'item-cardio-online-1',
                    descriptor: { name: 'Cardiology Consultation (Online)', code: 'Consultation' },
                    category_id: 'cardiology',
                    fulfillment_id: 'online',
                    price: { currency: 'INR', value: '500' },
                    time: { range: { start: '2026-10-01T09:00:00', end: '2026-10-01T09:30:00' } },
                },
                {
                    id: 'item-derma-online-1',
                    descriptor: { name: 'Dermatology Consultation (Online)', code: 'Consultation' },
                    category_id: 'dermatology',
                    fulfillment_id: 'online',
                    price: { currency: 'INR', value: '400' },
                    time: { range: { start: '2026-10-01T10:00:00', end: '2026-10-01T10:30:00' } },
                },
            ],
        },
    ],
};

export async function loadCatalog(store) {
    const published = await store.get(CATALOG_KEY);
    return published ?? FIXTURE_CATALOG;
}

export function parseCatalog(input) {
    return CatalogSchema.parse(input);
}

/** Returns only matching items if the intent names an item or category code, otherwise the
 * whole catalog. A real HSPA would query its scheduling system here. */
export function searchCatalog(catalog, itemCode, categoryCode) {
    if (!itemCode && !categoryCode) return catalog;
    const eq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

    const providers = [];
    for (const provider of catalog.providers ?? []) {
        const items = (provider.items ?? []).filter((item) => {
            const category = provider.categories?.find((c) => c.id === item.category_id);
            return (itemCode && eq(item.descriptor?.code, itemCode)) || (categoryCode && eq(category?.descriptor?.code, categoryCode));
        });
        if (items.length > 0) providers.push({ ...provider, items });
    }
    return { descriptor: catalog.descriptor, providers };
}

/** @returns {{ item: object, provider: object } | undefined} */
export function findItem(catalog, itemId) {
    for (const provider of catalog.providers ?? []) {
        const item = (provider.items ?? []).find((i) => i.id === itemId);
        if (item) return { item, provider };
    }
    return undefined;
}
