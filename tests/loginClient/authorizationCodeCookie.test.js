import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

import { LoginClient, PersistenceType } from '../../src/index.js';
import jwtManager from '../../src/jwtManager.js';
import userIdentityTokenStorageManager from '../../src/userIdentityTokenStorageManager.js';
import { findCookieWrite } from '../helpers/browserCookies.js';
import { authorizationCode, issueAccessToken, issueIdToken } from '../helpers/authressTokens.js';

const authenticationRequestId = 'req_cookie_test';
const now = new Date('2026-11-06T12:00:00.000Z');
const oneHourFromNow = new Date('2026-11-06T13:00:00.000Z');
const accessToken = issueAccessToken({ issuedAt: now, expiresAt: oneHourFromNow });
const idToken = issueIdToken({ issuedAt: now, expiresAt: oneHourFromNow });

let loginClient;
let httpPostSpy;
let cookieWrites;

/**
 * Simulates the browser after the Authress hosted login redirects back with `code=cookie`, which means the authorization code was delivered in the `auth-code` cookie instead of the query string.
 * The cookie header is returned verbatim, rather than through a cookie jar, so that malformed headers a real browser can produce reach the parser unchanged.
 */
function stubReturnFromHostedLogin({ queryCode = 'cookie', cookieHeader }) {
  cookieWrites = [];
  const fakeDocument = {};
  Object.defineProperty(fakeDocument, 'cookie', { set(value) { cookieWrites.push(value); }, get: () => cookieHeader });
  vi.stubGlobal('document', fakeDocument);
  vi.stubGlobal('window', { location: new URL(`https://app.example.com/callback?code=${queryCode}&nonce=${authenticationRequestId}`) });
  vi.stubGlobal('history', { state: null, replaceState() {} });

  const localStorageItems = {
    AuthenticationRequestNonce: JSON.stringify({ nonce: authenticationRequestId, codeVerifier: 'code-verifier', redirectUrl: 'https://app.example.com/callback' })
  };
  vi.stubGlobal('localStorage', {
    getItem: key => localStorageItems[key] ?? null,
    setItem(key, value) { localStorageItems[key] = value; },
    removeItem(key) { delete localStorageItems[key]; }
  });
}

const exchangedAuthorizationCode = () => httpPostSpy.mock.calls[0][2].code;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(now);
  loginClient = new LoginClient({ authressApiUrl: 'https://login.example.com', applicationId: 'app_test', skipBackgroundCredentialsCheck: true });
  httpPostSpy = vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: idToken, expires_in: 3600 } });
  vi.spyOn(loginClient.logger, 'log').mockImplementation(() => {});
  vi.spyOn(jwtManager, 'calculateAntiAbuseHash').mockResolvedValue('anti-abuse-hash');
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  userIdentityTokenStorageManager.persistenceType = PersistenceType.Cookie;
});

describe('loginClient.js', () => {
  describe('userSessionContinuation with the authorization code delivered by cookie', () => {
    it('should exchange the auth-code cookie value for tokens', async () => {
      stubReturnFromHostedLogin({ cookieHeader: `auth-code=${authorizationCode}` });

      const result = await loginClient.userSessionContinuation();

      expect(result).toEqual(true);
      expect(httpPostSpy).toHaveBeenCalledWith(`/authentication/${authenticationRequestId}/tokens`, false, expect.objectContaining({
        grant_type: 'authorization_code', code: authorizationCode, code_verifier: 'code-verifier', redirect_uri: 'https://app.example.com/callback'
      }));
    });

    it('should pass the same auth-code cookie value into the anti abuse hash that is sent to the token exchange', async () => {
      stubReturnFromHostedLogin({ cookieHeader: `auth-code=${authorizationCode}` });

      await loginClient.userSessionContinuation();

      expect(jwtManager.calculateAntiAbuseHash).toHaveBeenCalledWith({ client_id: 'app_test', authenticationRequestId, code: authorizationCode });
    });

    it('should find the auth-code cookie among the cookies the SDK and the application set on the site', async () => {
      stubReturnFromHostedLogin({ cookieHeader: `theme=dark; authorization=${accessToken}; auth-code=${authorizationCode}; user=${idToken}; AuthUserId=google|112233445566778899001` });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual(authorizationCode);
    });

    it('should ignore spaces around the cookie name and value', async () => {
      stubReturnFromHostedLogin({ cookieHeader: `theme=dark;   auth-code =  ${authorizationCode}  ;user=identity` });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual(authorizationCode);
    });

    it('should ignore tabs around the cookie name and value', async () => {
      stubReturnFromHostedLogin({ cookieHeader: `theme=dark;\tauth-code=\t${authorizationCode}\t` });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual(authorizationCode);
    });

    it('should ignore a trailing semicolon after the auth-code cookie', async () => {
      stubReturnFromHostedLogin({ cookieHeader: `auth-code=${authorizationCode};` });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual(authorizationCode);
    });

    it('should keep the equals sign padding of a base64 auth-code cookie value', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'auth-code=q8/Zr+9TfE2Xg0kH7v1mUw==; theme=dark' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('q8/Zr+9TfE2Xg0kH7v1mUw==');
    });

    it('should percent-decode the auth-code cookie value', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'auth-code=q8%2FZr%2B9TfE2Xg0kH7v1mUw%3D%3D' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('q8/Zr+9TfE2Xg0kH7v1mUw==');
    });

    it('should percent-decode non-ascii characters as utf-8', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'auth-code=caf%C3%A9' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('café');
    });

    it('should exchange a base64url auth-code containing tildes without altering any of its characters', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'auth-code=XFhyO-qcZtEuzhJdbYslHdN3BTgPO4CB~YN1XzhRrRaZc' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('XFhyO-qcZtEuzhJdbYslHdN3BTgPO4CB~YN1XzhRrRaZc');
    });

    it('should decode a tilde that was percent-encoded by an encoder that treats it as reserved', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'auth-code=XFhyO-qcZtEuzhJdbYslHdN3BTgPO4CB%7EYN1XzhRrRaZc' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('XFhyO-qcZtEuzhJdbYslHdN3BTgPO4CB~YN1XzhRrRaZc');
    });

    it('should not convert a plus sign into a space, because cookies are not form encoded', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'auth-code=code+from+cookie' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('code+from+cookie');
    });

    it('should keep the raw auth-code cookie value when its percent-encoding is malformed', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'auth-code=code%E0%A4%A' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('code%E0%A4%A');
    });

    it('should use the first auth-code cookie when the browser sends more than one, because browsers list the most specific path first', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'auth-code=code_for_callback_path; auth-code=code_for_root_path' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('code_for_callback_path');
    });

    it('should find the auth-code cookie after a cookie that has no equals sign', async () => {
      stubReturnFromHostedLogin({ cookieHeader: `consent_given; auth-code=${authorizationCode}` });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual(authorizationCode);
    });

    it('should find the auth-code cookie when the site has a cookie named after an object prototype property', async () => {
      stubReturnFromHostedLogin({ cookieHeader: `__proto__=polluted; constructor=polluted; auth-code=${authorizationCode}` });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual(authorizationCode);
    });

    it('should exchange an empty code when the auth-code cookie is present but empty', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'auth-code=; theme=dark' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('');
    });

    it('should not treat cookies whose names only contain auth-code as the authorization code', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'my-auth-code=wrong_code; auth-code-backup=wrong_code' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toBeUndefined();
    });

    it('should not treat a cookie named auth-code with different casing as the authorization code, because cookie names are case sensitive', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'Auth-Code=wrong_code; AUTH-CODE=wrong_code' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toBeUndefined();
    });

    it('should exchange an undefined code when the auth-code cookie is missing', async () => {
      stubReturnFromHostedLogin({ cookieHeader: 'theme=dark; user=identity' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toBeUndefined();
    });

    it('should exchange an undefined code when the site has no cookies', async () => {
      stubReturnFromHostedLogin({ cookieHeader: '' });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toBeUndefined();
    });

    it('should exchange the query string code and ignore the auth-code cookie when the code is delivered in the query string', async () => {
      stubReturnFromHostedLogin({ queryCode: 'code_from_query', cookieHeader: `auth-code=${authorizationCode}` });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('code_from_query');
    });

    it('should store the exchanged access token in the authorization cookie', async () => {
      stubReturnFromHostedLogin({ cookieHeader: `auth-code=${authorizationCode}` });

      await loginClient.userSessionContinuation();

      expect(findCookieWrite(cookieWrites, 'authorization')).toEqual({
        name: 'authorization',
        value: accessToken,
        attributes: { path: '/', expires: 'Fri, 06 Nov 2026 12:59:50 GMT', samesite: 'Strict', secure: true }
      });
    });
  });
});
