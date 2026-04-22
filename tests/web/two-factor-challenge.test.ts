import test from 'node:test';
import assert from 'node:assert/strict';
import { parseTwoFactorChallenge } from '../../webapp/src/lib/app-auth.ts';

test('parseTwoFactorChallenge keeps provider ids and metadata', () => {
  assert.deepEqual(
    parseTwoFactorChallenge({
      TwoFactorProviders: ['3', '0', '-1'],
      TwoFactorProviders2: {
        '0': null,
        '3': { Nfc: true },
      },
    }),
    {
      availableProviders: ['3', '0'],
      preferredProvider: '0',
      providerData: {
        '0': null,
        '3': { Nfc: true },
      },
    },
  );
});

test('parseTwoFactorChallenge prefers yubikey when authenticator is absent', () => {
  assert.deepEqual(
    parseTwoFactorChallenge({
      TwoFactorProviders: ['3'],
      TwoFactorProviders2: { '3': { Nfc: false } },
    }),
    {
      availableProviders: ['3'],
      preferredProvider: '3',
      providerData: {
        '3': { Nfc: false },
      },
    },
  );
});
