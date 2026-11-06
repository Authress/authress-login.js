// @vitest-environment jsdom
import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

import { LoginClient, PersistenceType } from '../../src/index.js';
import jwtManager from '../../src/jwtManager.js';
import userIdentityTokenStorageManager from '../../src/userIdentityTokenStorageManager.js';
import { browseTo, clearBrowserState, serverSetsCookie, storedCookie } from '../helpers/jsdomBrowser.js';
import { authorizationCode, issueAccessToken, issueIdToken } from '../helpers/authressTokens.js';

const authenticationRequestId = 'req_cookie_test';
const now = new Date('2026-11-06T12:00:00.000Z');
const oneHourFromNow = new Date('2026-11-06T13:00:00.000Z');
const accessToken = issueAccessToken({ issuedAt: now, expiresAt: oneHourFromNow });
const idToken = issueIdToken({ issuedAt: now, expiresAt: oneHourFromNow });
const hostedLoginUrl = 'https://login.example.com/';

let loginClient;
let httpPostSpy;

/**
 * Simulates the Authress hosted login on the custom domain setting the `auth-code` cookie for the parent domain, then redirecting back to the application with `code=cookie`.
 */
async function returnFromHostedLogin({ queryCode = 'cookie', authCodeSetCookieHeaders = [] }) {
  for (const setCookieHeader of authCodeSetCookieHeaders) {
    await serverSetsCookie(setCookieHeader, hostedLoginUrl);
  }
  browseTo(`https://app.example.com/callback?code=${queryCode}&nonce=${authenticationRequestId}`);
  localStorage.setItem('AuthenticationRequestNonce', JSON.stringify({ nonce: authenticationRequestId, codeVerifier: 'code-verifier', redirectUrl: 'https://app.example.com/callback' }));
}

const authCodeCookieFromHostedLogin = value => `auth-code=${value}; Domain=example.com; Path=/; Secure; SameSite=Lax`;
const exchangedAuthorizationCode = () => httpPostSpy.mock.calls[0][2].code;

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(now);
  browseTo('https://app.example.com/');
  loginClient = new LoginClient({ authressApiUrl: 'https://login.example.com', applicationId: 'app_test', skipBackgroundCredentialsCheck: true });
  httpPostSpy = vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: idToken, expires_in: 3600 } });
  vi.spyOn(loginClient.logger, 'log').mockImplementation(() => {});
  vi.spyOn(jwtManager, 'calculateAntiAbuseHash').mockResolvedValue('anti-abuse-hash');
});

afterEach(async () => {
  await clearBrowserState();
  vi.useRealTimers();
  vi.restoreAllMocks();
  userIdentityTokenStorageManager.persistenceType = PersistenceType.Cookie;
});

describe('loginClient.js in a browser', () => {
  describe('userSessionContinuation with the authorization code delivered by cookie', () => {
    it('should exchange the auth-code cookie value for tokens', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin(authorizationCode)] });

      const result = await loginClient.userSessionContinuation();

      expect(result).toEqual(true);
      expect(httpPostSpy).toHaveBeenCalledWith(`/authentication/${authenticationRequestId}/tokens`, true, expect.objectContaining({
        grant_type: 'authorization_code', code: authorizationCode, code_verifier: 'code-verifier', redirect_uri: 'https://app.example.com/callback'
      }));
    });

    it('should pass the same auth-code cookie value into the anti abuse hash that is sent to the token exchange', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin(authorizationCode)] });

      await loginClient.userSessionContinuation();

      expect(jwtManager.calculateAntiAbuseHash).toHaveBeenCalledWith({ client_id: 'app_test', authenticationRequestId, code: authorizationCode });
    });

    it('should find the auth-code cookie among the cookies the SDK and the application set on the site', async () => {
      browseTo('https://app.example.com/');
      document.cookie = 'theme=dark; Path=/';
      document.cookie = `authorization=${accessToken}; Path=/`;
      document.cookie = `user=${idToken}; Path=/`;
      document.cookie = 'AuthUserId=google|112233445566778899001; Path=/';
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin(authorizationCode)] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual(authorizationCode);
    });

    it('should ignore spaces the server puts around the cookie name and value', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [`auth-code =  ${authorizationCode}  ; Domain=example.com; Path=/; Secure`] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual(authorizationCode);
    });

    it('should exchange a base64url auth-code containing tildes without altering any of its characters', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin('XFhyO-qcZtEuzhJdbYslHdN3BTgPO4CB~YN1XzhRrRaZc')] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('XFhyO-qcZtEuzhJdbYslHdN3BTgPO4CB~YN1XzhRrRaZc');
    });

    it('should decode a tilde that the server percent-encoded with an encoder that treats it as reserved', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin('XFhyO-qcZtEuzhJdbYslHdN3BTgPO4CB%7EYN1XzhRrRaZc')] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('XFhyO-qcZtEuzhJdbYslHdN3BTgPO4CB~YN1XzhRrRaZc');
    });

    it('should keep the equals sign padding of a base64 auth-code cookie value', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin('q8/Zr+9TfE2Xg0kH7v1mUw==')] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('q8/Zr+9TfE2Xg0kH7v1mUw==');
    });

    it('should percent-decode the auth-code cookie value', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin('q8%2FZr%2B9TfE2Xg0kH7v1mUw%3D%3D')] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('q8/Zr+9TfE2Xg0kH7v1mUw==');
    });

    it('should percent-decode non-ascii characters as utf-8', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin('caf%C3%A9')] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('café');
    });

    it('should not convert a plus sign into a space, because cookies are not form encoded', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin('code+from+cookie')] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('code+from+cookie');
    });

    it('should keep the raw auth-code cookie value when its percent-encoding is malformed', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin('code%E0%A4%A')] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('code%E0%A4%A');
    });

    it('should use the auth-code cookie set for the callback path over one set for the whole site, because browsers list the most specific path first', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [
        'auth-code=code_for_root_path; Domain=example.com; Path=/; Secure',
        'auth-code=code_for_callback_path; Domain=example.com; Path=/callback; Secure'
      ] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('code_for_callback_path');
    });

    it('should find the auth-code cookie after a cookie that has no equals sign', async () => {
      document.cookie = 'consent_given';
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin(authorizationCode)] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual(authorizationCode);
    });

    it('should find the auth-code cookie when the site has a cookie named after an object prototype property', async () => {
      document.cookie = '__proto__=polluted; Path=/';
      document.cookie = 'constructor=polluted; Path=/';
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin(authorizationCode)] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual(authorizationCode);
    });

    it('should exchange an empty code when the auth-code cookie is present but empty', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin('')] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('');
    });

    it('should not treat cookies whose names only contain auth-code as the authorization code', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: ['my-auth-code=wrong_code; Domain=example.com; Path=/', 'auth-code-backup=wrong_code; Domain=example.com; Path=/'] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toBeUndefined();
    });

    it('should not treat a cookie named auth-code with different casing as the authorization code, because cookie names are case sensitive', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: ['Auth-Code=wrong_code; Domain=example.com; Path=/', 'AUTH-CODE=wrong_code; Domain=example.com; Path=/'] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toBeUndefined();
    });

    it('should not exchange an auth-code cookie set for a different site', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [] });
      await serverSetsCookie(`auth-code=${authorizationCode}; Path=/; Secure`, 'https://login.other-site.com/');

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toBeUndefined();
    });

    it('should not exchange an auth-code cookie that expired before the user returned to the application', async () => {
      await serverSetsCookie(`auth-code=${authorizationCode}; Domain=example.com; Path=/; Secure; Max-Age=60`, hostedLoginUrl);
      vi.setSystemTime(new Date('2026-11-06T12:01:01.000Z'));
      await returnFromHostedLogin({});

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toBeUndefined();
    });

    it('should exchange an undefined code when the auth-code cookie is missing', async () => {
      document.cookie = 'theme=dark; Path=/';
      await returnFromHostedLogin({});

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toBeUndefined();
    });

    it('should exchange an undefined code when the site has no cookies', async () => {
      await returnFromHostedLogin({});

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toBeUndefined();
    });

    it('should exchange the query string code and ignore the auth-code cookie when the code is delivered in the query string', async () => {
      await returnFromHostedLogin({ queryCode: 'code_from_query', authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin(authorizationCode)] });

      await loginClient.userSessionContinuation();

      expect(exchangedAuthorizationCode()).toEqual('code_from_query');
    });

    it('should store the exchanged access token in the authorization cookie', async () => {
      await returnFromHostedLogin({ authCodeSetCookieHeaders: [authCodeCookieFromHostedLogin(authorizationCode)] });

      await loginClient.userSessionContinuation();

      expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, path: '/', expires: new Date('2026-11-06T12:59:50.000Z'), sameSite: 'strict', secure: true });
      expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([accessToken]);
    });
  });
});
