import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeYubikeyStatusResponse } from '../../webapp/src/lib/api/auth.ts';

test('normalizeYubikeyStatusResponse trims ids and falls back to keys when publicIds is absent', () => {
  assert.deepEqual(
    normalizeYubikeyStatusResponse({
      enabled: true,
      keys: [' cccccccccccc ', '', 'dddddddddddd'],
      nfc: true,
    }),
    {
      enabled: true,
      publicIds: ['cccccccccccc', 'dddddddddddd'],
      nfc: true,
    },
  );
});
