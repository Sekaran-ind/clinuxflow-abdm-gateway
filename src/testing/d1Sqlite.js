// Tests only: a D1-shaped wrapper over node:sqlite, loaded with the shared `clinuxflow` database's
// schema so SQL is tested as SQLite runs it. The schema's home is clinuxflow-api/migrations; the
// files this gateway's tests need are copied into ./schema (CI checks out this repo alone), and
// schema.test.js fails if a copy drifts from clinuxflow-api's when that repo sits alongside.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const SCHEMA_DIR = fileURLToPath(new URL('./schema/', import.meta.url));

export function d1(migrations = []) {
    const db = new DatabaseSync(':memory:');
    for (const m of migrations) db.exec(readFileSync(`${SCHEMA_DIR}${m}`, 'utf8'));
    const statement = (sql, args = []) => ({
        bind: (...a) => statement(sql, a),
        first: async () => db.prepare(sql).get(...args) ?? null,
        all: async () => ({ results: db.prepare(sql).all(...args) }),
        run: async () => ({ success: true, meta: { changes: Number(db.prepare(sql).run(...args).changes) } }),
    });
    return { prepare: (sql) => statement(sql), raw: db };
}
