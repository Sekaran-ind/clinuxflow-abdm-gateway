// The schema copies in ./schema must match clinuxflow-api's migrations, the source of truth.
// Checked only where clinuxflow-api is checked out next to this repo (local dev); CI has this repo alone.
import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SCHEMA_DIR } from './d1Sqlite.js';

const API_MIGRATIONS = fileURLToPath(new URL('../../../clinuxflow-api/migrations/', import.meta.url));

describe.skipIf(!existsSync(API_MIGRATIONS))('schema copies', () => {
    it.each(readdirSync(SCHEMA_DIR).filter((f) => f.endsWith('.sql')))('%s matches clinuxflow-api', (file) => {
        expect(readFileSync(`${SCHEMA_DIR}${file}`, 'utf8')).toBe(readFileSync(`${API_MIGRATIONS}${file}`, 'utf8'));
    });
});
