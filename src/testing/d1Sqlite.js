// Tests only: a D1-shaped wrapper over node:sqlite, loaded with clinuxflow-api's real migrations
// (the shared `clinuxflow` database's schema lives there), so SQL is tested as SQLite runs it.
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const MIGRATIONS = fileURLToPath(new URL('../../../clinuxflow-api/migrations/', import.meta.url));

export function d1(migrations = []) {
    const db = new DatabaseSync(':memory:');
    for (const m of migrations) db.exec(readFileSync(`${MIGRATIONS}${m}`, 'utf8'));
    const statement = (sql, args = []) => ({
        bind: (...a) => statement(sql, a),
        first: async () => db.prepare(sql).get(...args) ?? null,
        all: async () => ({ results: db.prepare(sql).all(...args) }),
        run: async () => ({ success: true, meta: { changes: Number(db.prepare(sql).run(...args).changes) } }),
    });
    return { prepare: (sql) => statement(sql), raw: db };
}
