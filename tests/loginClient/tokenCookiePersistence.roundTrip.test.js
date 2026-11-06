// @vitest-environment jsdom
import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

import { LoginClient, PersistenceType } from '../../src/index.js';
import jwtManager from '../../src/jwtManager.js';
import userIdentityTokenStorageManager from '../../src/userIdentityTokenStorageManager.js';
import { browseTo, clearBrowserState, storedCookie } from '../helpers/jsdomBrowser.js';
import { issueAccessToken, issueIdToken, sessionToken } from '../helpers/authressTokens.js';

const authenticationRequestId = 'req_cookie_test';
const now = new Date('2026-11-06T12:00:00.000Z');
const oneHourFromNow = new Date('2026-11-06T13:00:00.000Z');
const accessToken = issueAccessToken({ issuedAt: now, expiresAt: oneHourFromNow });
const idToken = issueIdToken({ issuedAt: now, expiresAt: oneHourFromNow });
const idTokenWithoutExpiry = issueIdToken({ issuedAt: now });

let loginClient;

function returnFromHostedLoginWithCode() {
  browseTo(`https://app.example.com/callback?code=code_from_query&nonce=${authenticationRequestId}`);
  localStorage.setItem('AuthenticationRequestNonce', JSON.stringify({ nonce: authenticationRequestId, codeVerifier: 'code-verifier', redirectUrl: 'https://app.example.com/callback' }));
}

/**
 * Localhost development cannot receive the cross site Authress cookies, so the hosted login hands the tokens back in the query string instead.
 */
function returnFromHostedLoginOnLocalhost(queryParameters) {
  const location = new URL('http://localhost:8080/');
  Object.entries({ nonce: authenticationRequestId, ...queryParameters }).forEach(([key, value]) => location.searchParams.set(key, value));
  browseTo(location.toString());
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(now);
  browseTo('https://app.example.com/dashboard');
  loginClient = new LoginClient({ authressApiUrl: 'https://login.example.com', applicationId: 'app_test', skipBackgroundCredentialsCheck: true });
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
  describe('userSessionContinuation persisting tokens to cookies', () => {
    describe('after exchanging the authorization code', () => {
      it('should expire the authorization cookie ten seconds before the id token expires, to avoid using a token in its final seconds', async () => {
        returnFromHostedLoginWithCode();
        vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: idToken, expires_in: 3600 } });

        await loginClient.userSessionContinuation();

        expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, path: '/', expires: new Date('2026-11-06T12:59:50.000Z'), sameSite: 'strict', secure: true });
      });

      it('should keep an id token expiry that is more than two years away for the authorization cookie', async () => {
        returnFromHostedLoginWithCode();
        const longLivedIdToken = issueIdToken({ issuedAt: now, expiresAt: new Date('2029-01-01T00:00:00.000Z') });
        vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: longLivedIdToken, expires_in: 3600 } });

        await loginClient.userSessionContinuation();

        expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, expires: new Date('2028-12-31T23:59:50.000Z') });
        expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([accessToken]);
      });

      it('should expire the authorization cookie after expires_in when the id token has no expiry', async () => {
        returnFromHostedLoginWithCode();
        vi.setSystemTime(new Date('2026-11-06T12:00:00.500Z'));
        vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: idTokenWithoutExpiry, expires_in: 3600 } });

        await loginClient.userSessionContinuation();

        expect((await await storedCookie('authorization')).expires).toEqual(new Date('2026-11-06T13:00:00.000Z'));
      });

      it('should store the authorization cookie as a browser session cookie when neither the id token nor the response has an expiry', async () => {
        returnFromHostedLoginWithCode();
        vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: idTokenWithoutExpiry } });

        await loginClient.userSessionContinuation();

        expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, path: '/', sameSite: 'strict', secure: true });
        expect((await await storedCookie('authorization')).isPersistent()).toEqual(false);
      });

      it('should make the exchanged access token readable to the application', async () => {
        returnFromHostedLoginWithCode();
        vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: idToken, expires_in: 3600 } });

        await loginClient.userSessionContinuation();

        expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([accessToken]);
      });
    });

    describe('after the hosted login returns the tokens to localhost', () => {
      it('should store the authorization cookie without the secure flag, because localhost is served over http', async () => {
        returnFromHostedLoginOnLocalhost({ access_token: accessToken, id_token: idToken, expires_in: '3600', session_token: sessionToken });

        await loginClient.userSessionContinuation();

        expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, path: '/', expires: new Date('2026-11-06T12:59:50.000Z'), sameSite: 'strict', secure: false });
        expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([accessToken]);
      });

      it('should keep the session cookie for ninety days so that the user stays logged in across access token expiries', async () => {
        returnFromHostedLoginOnLocalhost({ access_token: accessToken, id_token: idToken, expires_in: '3600', session_token: sessionToken });

        await loginClient.userSessionContinuation();

        expect(await storedCookie('authress-session')).toMatchObject({ value: sessionToken, path: '/', expires: new Date('2027-02-04T12:00:00.000Z'), sameSite: 'strict', secure: false });
      });

      it('should store an empty session cookie when the hosted login does not return a session token', async () => {
        returnFromHostedLoginOnLocalhost({ access_token: accessToken, id_token: idToken, expires_in: '3600' });

        await loginClient.userSessionContinuation();

        expect(await storedCookie('authress-session')).toMatchObject({ value: '' });
      });

      it('should expire the authorization cookie after expires_in when the id token has no expiry', async () => {
        returnFromHostedLoginOnLocalhost({ access_token: accessToken, id_token: idTokenWithoutExpiry, expires_in: '3600' });

        await loginClient.userSessionContinuation();

        expect((await await storedCookie('authorization')).expires).toEqual(new Date('2026-11-06T13:00:00.000Z'));
      });

      it('should store the authorization cookie as a browser session cookie when neither the id token nor the query string has an expiry', async () => {
        returnFromHostedLoginOnLocalhost({ access_token: accessToken, id_token: idTokenWithoutExpiry });

        await loginClient.userSessionContinuation();

        expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, path: '/', sameSite: 'strict' });
        expect((await await storedCookie('authorization')).isPersistent()).toEqual(false);
      });
    });

    describe('after continuing an existing Authress session', () => {
      it('should store the access token returned for the session in the authorization cookie', async () => {
        vi.spyOn(loginClient.httpClient, 'patch').mockResolvedValue({ data: { access_token: accessToken, id_token: idToken, expires_in: 3600 } });

        const result = await loginClient.userSessionContinuation();

        expect(result).toEqual(true);
        expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, path: '/', expires: new Date('2026-11-06T12:59:50.000Z'), sameSite: 'strict', secure: true });
        expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([accessToken]);
      });

      it('should not store the authorization cookie when the session is held only in Authress cookies hidden from javascript', async () => {
        vi.spyOn(loginClient.httpClient, 'patch').mockResolvedValue({ data: {} });

        await loginClient.userSessionContinuation();

        expect(await storedCookie('authorization')).toBeUndefined();
      });
    });
  });
});
