import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

import { LoginClient, PersistenceType } from '../../src/index.js';
import jwtManager from '../../src/jwtManager.js';
import userIdentityTokenStorageManager from '../../src/userIdentityTokenStorageManager.js';
import { findCookieWrite, stubBrowserCookieJar } from '../helpers/browserCookies.js';
import { issueAccessToken, issueIdToken, sessionToken } from '../helpers/authressTokens.js';

const authenticationRequestId = 'req_cookie_test';
const now = new Date('2026-11-06T12:00:00.000Z');
const oneHourFromNow = new Date('2026-11-06T13:00:00.000Z');
const accessToken = issueAccessToken({ issuedAt: now, expiresAt: oneHourFromNow });
const idToken = issueIdToken({ issuedAt: now, expiresAt: oneHourFromNow });
const idTokenWithoutExpiry = issueIdToken({ issuedAt: now });

let loginClient;
let cookieWrites;
let localStorageItems;

function stubLocalStorage(initialItems = {}) {
  localStorageItems = { ...initialItems };
  vi.stubGlobal('localStorage', {
    getItem: key => localStorageItems[key] ?? null,
    setItem(key, value) { localStorageItems[key] = value; },
    removeItem(key) { delete localStorageItems[key]; }
  });
}

function stubReturnFromHostedLoginWithCode() {
  ({ cookieWrites } = stubBrowserCookieJar(`https://app.example.com/callback?code=code_from_query&nonce=${authenticationRequestId}`));
  vi.stubGlobal('history', { state: null, replaceState() {} });
  stubLocalStorage({ AuthenticationRequestNonce: JSON.stringify({ nonce: authenticationRequestId, codeVerifier: 'code-verifier', redirectUrl: 'https://app.example.com/callback' }) });
}

/**
 * Localhost development cannot receive the cross site Authress cookies, so the hosted login hands the tokens back in the query string instead.
 */
function stubReturnFromHostedLoginOnLocalhost(queryParameters) {
  const location = new URL('http://localhost:8080/');
  Object.entries({ nonce: authenticationRequestId, ...queryParameters }).forEach(([key, value]) => location.searchParams.set(key, value));
  ({ cookieWrites } = stubBrowserCookieJar(location.toString()));
  vi.stubGlobal('history', { state: null, replaceState() {} });
  stubLocalStorage();
}

function stubReturningUserWithExistingSession() {
  ({ cookieWrites } = stubBrowserCookieJar('https://app.example.com/dashboard'));
  stubLocalStorage();
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(now);
  loginClient = new LoginClient({ authressApiUrl: 'https://login.example.com', applicationId: 'app_test', skipBackgroundCredentialsCheck: true });
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
  describe('userSessionContinuation persisting tokens to cookies', () => {
    describe('after exchanging the authorization code', () => {
      it('should expire the authorization cookie ten seconds before the id token expires, to avoid using a token in its final seconds', async () => {
        stubReturnFromHostedLoginWithCode();
        vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: idToken, expires_in: 3600 } });

        await loginClient.userSessionContinuation();

        expect(findCookieWrite(cookieWrites, 'authorization')).toEqual({
          name: 'authorization',
          value: accessToken,
          attributes: { path: '/', expires: 'Fri, 06 Nov 2026 12:59:50 GMT', samesite: 'Strict', secure: true }
        });
      });

      it('should keep an id token expiry that is more than two years away for the authorization cookie', async () => {
        stubReturnFromHostedLoginWithCode();
        const longLivedIdToken = issueIdToken({ issuedAt: now, expiresAt: new Date('2029-01-01T00:00:00.000Z') });
        vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: longLivedIdToken, expires_in: 3600 } });

        await loginClient.userSessionContinuation();

        expect(findCookieWrite(cookieWrites, 'authorization')).toEqual({
          name: 'authorization',
          value: accessToken,
          attributes: { path: '/', expires: 'Sun, 31 Dec 2028 23:59:50 GMT', samesite: 'Strict', secure: true }
        });
      });

      it('should expire the authorization cookie after expires_in when the id token has no expiry', async () => {
        stubReturnFromHostedLoginWithCode();
        vi.setSystemTime(new Date('2026-11-06T12:00:00.500Z'));
        vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: idTokenWithoutExpiry, expires_in: 3600 } });

        await loginClient.userSessionContinuation();

        expect(findCookieWrite(cookieWrites, 'authorization').attributes.expires).toEqual('Fri, 06 Nov 2026 13:00:00 GMT');
      });

      it('should write the authorization cookie as a browser session cookie when neither the id token nor the response has an expiry', async () => {
        stubReturnFromHostedLoginWithCode();
        vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: idTokenWithoutExpiry } });

        await loginClient.userSessionContinuation();

        expect(findCookieWrite(cookieWrites, 'authorization')).toEqual({
          name: 'authorization',
          value: accessToken,
          attributes: { path: '/', samesite: 'Strict', secure: true }
        });
      });

      it('should make the exchanged access token readable to the application', async () => {
        stubReturnFromHostedLoginWithCode();
        vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue({ data: { access_token: accessToken, id_token: idToken, expires_in: 3600 } });

        await loginClient.userSessionContinuation();

        expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([accessToken]);
      });
    });

    describe('after the hosted login returns the tokens to localhost', () => {
      it('should write the authorization cookie without the secure flag, because localhost is served over http', async () => {
        stubReturnFromHostedLoginOnLocalhost({ access_token: accessToken, id_token: idToken, expires_in: '3600', session_token: sessionToken });

        await loginClient.userSessionContinuation();

        expect(findCookieWrite(cookieWrites, 'authorization')).toEqual({
          name: 'authorization',
          value: accessToken,
          attributes: { path: '/', expires: 'Fri, 06 Nov 2026 12:59:50 GMT', samesite: 'Strict' }
        });
      });

      it('should keep the session cookie for ninety days so that the user stays logged in across access token expiries', async () => {
        stubReturnFromHostedLoginOnLocalhost({ access_token: accessToken, id_token: idToken, expires_in: '3600', session_token: sessionToken });

        await loginClient.userSessionContinuation();

        expect(findCookieWrite(cookieWrites, 'authress-session')).toEqual({
          name: 'authress-session',
          value: sessionToken,
          attributes: { path: '/', expires: 'Thu, 04 Feb 2027 12:00:00 GMT', samesite: 'Strict' }
        });
      });

      it('should write an empty session cookie when the hosted login does not return a session token', async () => {
        stubReturnFromHostedLoginOnLocalhost({ access_token: accessToken, id_token: idToken, expires_in: '3600' });

        await loginClient.userSessionContinuation();

        expect(findCookieWrite(cookieWrites, 'authress-session')).toMatchObject({ name: 'authress-session', value: '' });
      });

      it('should expire the authorization cookie after expires_in when the id token has no expiry', async () => {
        stubReturnFromHostedLoginOnLocalhost({ access_token: accessToken, id_token: idTokenWithoutExpiry, expires_in: '3600' });

        await loginClient.userSessionContinuation();

        expect(findCookieWrite(cookieWrites, 'authorization').attributes.expires).toEqual('Fri, 06 Nov 2026 13:00:00 GMT');
      });

      it('should write the authorization cookie as a browser session cookie when neither the id token nor the query string has an expiry', async () => {
        stubReturnFromHostedLoginOnLocalhost({ access_token: accessToken, id_token: idTokenWithoutExpiry });

        await loginClient.userSessionContinuation();

        expect(findCookieWrite(cookieWrites, 'authorization')).toEqual({
          name: 'authorization',
          value: accessToken,
          attributes: { path: '/', samesite: 'Strict' }
        });
      });
    });

    describe('after continuing an existing Authress session', () => {
      it('should store the access token returned for the session in the authorization cookie', async () => {
        stubReturningUserWithExistingSession();
        vi.spyOn(loginClient.httpClient, 'patch').mockResolvedValue({ data: { access_token: accessToken, id_token: idToken, expires_in: 3600 } });

        const result = await loginClient.userSessionContinuation();

        expect(result).toEqual(true);
        expect(findCookieWrite(cookieWrites, 'authorization')).toEqual({
          name: 'authorization',
          value: accessToken,
          attributes: { path: '/', expires: 'Fri, 06 Nov 2026 12:59:50 GMT', samesite: 'Strict', secure: true }
        });
      });

      it('should not write the authorization cookie when the session is held only in Authress cookies hidden from javascript', async () => {
        stubReturningUserWithExistingSession();
        vi.spyOn(loginClient.httpClient, 'patch').mockResolvedValue({ data: {} });

        await loginClient.userSessionContinuation();

        expect(findCookieWrite(cookieWrites, 'authorization')).toBeUndefined();
      });
    });
  });
});
