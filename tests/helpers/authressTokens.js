import { generateKeyPairSync, sign } from 'node:crypto';

const { privateKey } = generateKeyPairSync('ed25519');
const toBase64Url = value => Buffer.from(value).toString('base64url');

function signEdDsaJwt(header, payload) {
  const signingInput = `${toBase64Url(JSON.stringify(header))}.${toBase64Url(JSON.stringify(payload))}`;
  return `${signingInput}.${sign(null, Buffer.from(signingInput), privateKey).toString('base64url')}`;
}

/**
 * Issues an access token with the same signing algorithm and claim shape that the Authress token service returns, so cookie tests use the character set and length of production tokens.
 */
export function issueAccessToken({ issuedAt, expiresAt }) {
  return signEdDsaJwt({ alg: 'EdDSA', kid: 'kid_2xUbv1YqW8ns4qE9nGA4Hc', typ: 'at+jwt' }, {
    iss: 'https://login.example.com',
    sub: 'google|112233445566778899001',
    iat: Math.floor(issuedAt.getTime() / 1000),
    exp: Math.floor(expiresAt.getTime() / 1000),
    jti: 'google|112233445566778899001-239a6940-9890-11f0-b369-3fd68e261119',
    scope: 'openid profile email',
    azp: 'con_j1mVQTpzuouNH3vWxJDZyB',
    client_id: 'app_test',
    aud: ['https://api.example.com']
  });
}

/**
 * Issues an id token with the claim shape that the Authress token service returns. Omitting `expiresAt` reproduces identity providers that do not set `exp`, which forces the SDK to fall back to `expires_in`.
 */
export function issueIdToken({ issuedAt, expiresAt }) {
  return signEdDsaJwt({ alg: 'EdDSA', kid: 'kid_2xUbv1YqW8ns4qE9nGA4Hc', typ: 'JWT' }, {
    iss: 'https://login.example.com',
    sub: 'google|112233445566778899001',
    aud: 'app_test',
    iat: Math.floor(issuedAt.getTime() / 1000),
    exp: expiresAt ? Math.floor(expiresAt.getTime() / 1000) : undefined,
    name: 'Test User',
    email: 'test.user@example.com',
    email_verified: true,
    picture: 'https://secure.gravatar.com/avatar/8833fc2abe5b23d698667c7ae0046667.jpg?s=512&d=https%3A%2F%2Fa.slack-edge.com%2Fdf10d%2Fimg%2Favatars%2Fava_0025-512.png',
    locale: 'en-US'
  });
}

export const authorizationCode = 'XFhyO-qcZtEuzhJdbYslHdN3BTgPO4CB~YN1XzhRrRaZc';
export const sessionToken = 'k5cF4FMeVbODOtX_gLDaVKSvBHrMFgntFgpyXcDC~JDk301VNGpwM0H-EKLCI~lhU9-7MD';
