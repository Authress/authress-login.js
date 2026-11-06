import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

import userIdentityTokenStorageManager, { PersistenceType } from '../../src/userIdentityTokenStorageManager.js';
import { parseCookieWrite, stubBrowserCookieJar } from '../helpers/browserCookies.js';
import { issueAccessToken, issueIdToken, sessionToken } from '../helpers/authressTokens.js';

const now = new Date('2026-11-06T12:00:00.000Z');
const oneHourFromNow = new Date('2026-11-06T13:00:00.000Z');
const accessToken = issueAccessToken({ issuedAt: now, expiresAt: oneHourFromNow });

let cookieJar;
let cookieWrites;

const storeLocalStorageItems = () => {
  const localStorageItems = {};
  vi.stubGlobal('localStorage', {
    getItem: key => localStorageItems[key] ?? null,
    setItem(key, value) { localStorageItems[key] = value; },
    removeItem(key) { delete localStorageItems[key]; }
  });
};

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(now);
  ({ cookieJar, cookieWrites } = stubBrowserCookieJar('https://app.example.com/dashboard'));
  storeLocalStorageItems();
  userIdentityTokenStorageManager.persistenceType = PersistenceType.Cookie;
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('userIdentityTokenStorageManager.js', () => {
  describe('setCookie', () => {
    it('should write the authorization token as a site wide, strict, secure cookie expiring with the token', () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);

      expect(cookieWrites).toHaveLength(1);
      expect(parseCookieWrite(cookieWrites[0])).toEqual({
        name: 'authorization',
        value: accessToken,
        attributes: { path: '/', expires: 'Fri, 06 Nov 2026 13:00:00 GMT', samesite: 'Strict', secure: true }
      });
    });

    it('should write the session token under the authress-session cookie name', () => {
      userIdentityTokenStorageManager.setSessionToken(sessionToken, oneHourFromNow);

      expect(parseCookieWrite(cookieWrites[0])).toEqual({
        name: 'authress-session',
        value: sessionToken,
        attributes: { path: '/', expires: 'Fri, 06 Nov 2026 13:00:00 GMT', samesite: 'Strict', secure: true }
      });
    });

    it('should not mark the cookie secure when the site is served over http', () => {
      ({ cookieWrites } = stubBrowserCookieJar('http://localhost:8080/'));

      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);

      expect(parseCookieWrite(cookieWrites[0]).attributes).not.toHaveProperty('secure');
    });

    it('should drop the milliseconds of the expiry, because cookie dates only have second precision', () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, new Date('2026-11-06T13:00:00.789Z'));

      expect(parseCookieWrite(cookieWrites[0]).attributes.expires).toEqual('Fri, 06 Nov 2026 13:00:00 GMT');
    });

    it('should write an already passed expiry so that the browser removes the cookie', () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, new Date('2026-11-06T11:59:50.000Z'));

      expect(parseCookieWrite(cookieWrites[0]).attributes.expires).toEqual('Fri, 06 Nov 2026 11:59:50 GMT');
    });

    it.each([
      ['undefined, when no expiry is provided', undefined],
      ['null, when the token response has a null expires_in', null],
      ['0, when the localhost redirect has no expires_in query parameter', 0]
    ])('should write a browser session cookie without an expiry when the expiry is %s', (_, expiry) => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, expiry);

      expect(parseCookieWrite(cookieWrites[0])).toEqual({
        name: 'authorization',
        value: accessToken,
        attributes: { path: '/', samesite: 'Strict', secure: true }
      });
    });

    it('should write an empty cookie value when the token is undefined', () => {
      userIdentityTokenStorageManager.setSessionToken(undefined, oneHourFromNow);

      expect(parseCookieWrite(cookieWrites[0])).toMatchObject({ name: 'authress-session', value: '' });
    });

    it('should write an empty cookie value when the localhost redirect has no session_token query parameter', () => {
      userIdentityTokenStorageManager.setSessionToken(new URLSearchParams('').get('session_token'), oneHourFromNow);

      expect(parseCookieWrite(cookieWrites[0])).toMatchObject({ name: 'authress-session', value: '' });
    });

    it('should write an EdDSA signed Authress access token without altering any of its characters', () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);

      expect(parseCookieWrite(cookieWrites[0]).value).toEqual(accessToken);
    });

    it('should write a base64url session token containing tildes without altering any of its characters', () => {
      userIdentityTokenStorageManager.setSessionToken('k5cF4FMeVbODOtX_gLDaVKSvBHrMFgntFgpyXcDC~JDk301VNGpwM0H-EKLCI~lhU9-7MD', oneHourFromNow);

      expect(parseCookieWrite(cookieWrites[0]).value).toEqual('k5cF4FMeVbODOtX_gLDaVKSvBHrMFgntFgpyXcDC~JDk301VNGpwM0H-EKLCI~lhU9-7MD');
    });

    it('should refuse to write the cookie when the expiry is not a valid date', () => {
      expect(() => userIdentityTokenStorageManager.setAuthorizationToken(accessToken, new Date('not-a-date'))).toThrow(TypeError);
      expect(cookieWrites).toHaveLength(0);
    });

    it('should not write any cookie when running outside of a browser', () => {
      vi.unstubAllGlobals();

      expect(() => userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow)).not.toThrow();
      expect(cookieWrites).toHaveLength(0);
    });
  });

  describe('reading back the cookies written by setCookie', () => {
    it('should read back the exact access token that was written', () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);

      expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([accessToken]);
    });

    it('should read back only the latest access token after the token is refreshed', () => {
      const refreshedAccessToken = issueAccessToken({ issuedAt: oneHourFromNow, expiresAt: new Date('2026-11-06T14:00:00.000Z') });

      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);
      userIdentityTokenStorageManager.setAuthorizationToken(refreshedAccessToken, new Date('2026-11-06T14:00:00.000Z'));

      expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([refreshedAccessToken]);
    });

    it('should no longer read back the access token once it is written with an already passed expiry', () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, new Date('2026-11-06T11:59:50.000Z'));

      expect(cookieJar.has('authorization')).toEqual(false);
      expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([]);
    });

    it('should keep the stored user identity valid while the authorization cookie written alongside it is present', () => {
      const idToken = issueIdToken({ issuedAt: now, expiresAt: oneHourFromNow });

      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);
      userIdentityTokenStorageManager.set(idToken, oneHourFromNow);

      expect(userIdentityTokenStorageManager.get()).toEqual(idToken);
    });

    it('should invalidate the stored user identity once the authorization cookie written alongside it is removed', () => {
      const idToken = issueIdToken({ issuedAt: now, expiresAt: oneHourFromNow });
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);
      userIdentityTokenStorageManager.set(idToken, oneHourFromNow);

      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, new Date('2026-11-06T11:59:50.000Z'));

      expect(userIdentityTokenStorageManager.get()).toEqual(null);
    });
  });
});
