import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema.js';

const connectionOptions = {
  max: 10,
  idle_timeout: 20,
  connect_timeout: 10,
  prepare: false,
} as const;

export function createDatabase(databaseUrl: string) {
  // Drizzle mutates postgres.js date serializers/parsers on the client it receives.
  // Keep raw transactional SQL on an independent client so native postgres.js
  // Date serialization remains intact for commerce/reconciliation queries.
  const client = postgres(databaseUrl, connectionOptions);
  const drizzleClient = postgres(databaseUrl, connectionOptions);
  const db = drizzle(drizzleClient, { schema });

  // PostgresPlatformStore historically closes `client`; make that close both
  // physical pools so the split does not leak the Drizzle pool in tests/runtime.
  const rawEnd = client.end.bind(client);
  const drizzleEnd = drizzleClient.end.bind(drizzleClient);
  Object.defineProperty(client, 'end', {
    configurable: false,
    enumerable: true,
    writable: false,
    value: async (...args: Parameters<typeof client.end>) => {
      await Promise.all([rawEnd(...args), drizzleEnd(...args)]);
    },
  });

  return { client, db };
}

export type Database = ReturnType<typeof createDatabase>['db'];
