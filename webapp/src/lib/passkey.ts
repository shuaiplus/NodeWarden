function base64UrlToBytes(input: string): Uint8Array {
  const normalized = String(input || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function bytesToBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (const b of view) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function passkeySupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential;
}

export async function createPasskeyCredential(publicKey: Record<string, any>): Promise<any> {
  const options: PublicKeyCredentialCreationOptions = {
    ...(publicKey as PublicKeyCredentialCreationOptions),
    challenge: base64UrlToBytes(publicKey.challenge),
    user: {
      ...publicKey.user,
      id: base64UrlToBytes(publicKey.user.id),
    },
    excludeCredentials: Array.isArray(publicKey.excludeCredentials)
      ? publicKey.excludeCredentials.map((item: any) => ({ ...item, id: base64UrlToBytes(item.id) }))
      : [],
  };

  const credential = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential | null;
  if (!credential) throw new Error('Passkey creation was cancelled');
  const response = credential.response as AuthenticatorAttestationResponse;

  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      attestationObject: bytesToBase64Url(response.attestationObject),
    },
  };
}

export async function requestPasskeyAssertion(publicKey: Record<string, any>): Promise<any> {
  const options: PublicKeyCredentialRequestOptions = {
    ...(publicKey as PublicKeyCredentialRequestOptions),
    challenge: base64UrlToBytes(publicKey.challenge),
    allowCredentials: Array.isArray(publicKey.allowCredentials)
      ? publicKey.allowCredentials.map((item: any) => ({ ...item, id: base64UrlToBytes(item.id) }))
      : undefined,
  };

  const credential = (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential | null;
  if (!credential) throw new Error('Passkey login was cancelled');
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      authenticatorData: bytesToBase64Url(response.authenticatorData),
      signature: bytesToBase64Url(response.signature),
      userHandle: response.userHandle ? bytesToBase64Url(response.userHandle) : null,
    },
  };
}
