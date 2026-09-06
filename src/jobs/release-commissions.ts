import { loadConfig } from '../config.js';
import { PostgresPlatformStore } from '../db/store-postgres.js';

const config = loadConfig();
if (!config.DATABASE_URL) throw new Error('DATABASE_URL is required');
const store = new PostgresPlatformStore(config.DATABASE_URL);
try {
  const result = await store.releaseEligibleCommissions(new Date(), 100);
  console.log(JSON.stringify({ released: result.released, amount_minor: result.amountMinor.toString(), currency: 'USD' }));
} finally {
  await store.close();
}
