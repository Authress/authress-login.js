// @vitest-environment jsdom
import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

import userIdentityTokenStorageManager, { PersistenceType } from '../../src/userIdentityTokenStorageManager.js';
import { browseTo, clearBrowserState, storedCookie } from '../helpers/jsdomBrowser.js';
import { issueAccessToken, issueIdToken, sessionToken } from '../helpers/authressTokens.js';

const now = new Date('2026-11-06T12:00:00.000Z');
const oneHourFromNow = new Date('2026-11-06T13:00:00.000Z');
const accessToken = issueAccessToken({ issuedAt: now, expiresAt: oneHourFromNow });

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(now);
  browseTo('https://app.example.com/dashboard');
  userIdentityTokenStorageManager.persistenceType = PersistenceType.Cookie;
});

afterEach(async () => {
  await clearBrowserState();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('userIdentityTokenStorageManager.js in a browser', () => {
  describe('setCookie', () => {
    it('should store the authorization token as a site wide, strict, secure cookie expiring with the token', async () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);

      expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, path: '/', expires: oneHourFromNow, sameSite: 'strict', secure: true, hostOnly: true });
    });

    it('should store the session token under the authress-session cookie name', async () => {
      userIdentityTokenStorageManager.setSessionToken(sessionToken, oneHourFromNow);

      expect(await storedCookie('authress-session')).toMatchObject({ value: sessionToken, path: '/', expires: oneHourFromNow, sameSite: 'strict', secure: true });
    });

    it('should store the cookie without the secure flag when the site is served over http, because browsers reject secure cookies from insecure origins', async () => {
      browseTo('http://app.example.com/dashboard');

      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);

      expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, secure: false });
    });

    it('should store the cookie without the secure flag on localhost', async () => {
      browseTo('http://localhost:8080/');

      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);

      expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, secure: false });
    });

    it('should drop the milliseconds of the expiry, because cookie dates only have second precision', async () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, new Date('2026-11-06T13:00:00.789Z'));

      expect((await await storedCookie('authorization')).expires).toEqual(new Date('2026-11-06T13:00:00.000Z'));
    });

    it('should not store a cookie whose expiry has already passed', async () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, new Date('2026-11-06T11:59:50.000Z'));

      expect(await storedCookie('authorization')).toBeUndefined();
    });

    it('should stop returning the cookie once its expiry passes', async () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);

      vi.setSystemTime(new Date('2026-11-06T13:00:01.000Z'));

      expect(await storedCookie('authorization')).toBeUndefined();
      expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([]);
    });

    it.each([
      ['undefined, when no expiry is provided', undefined],
      ['null, when the token response has a null expires_in', null],
      ['0, when the localhost redirect has no expires_in query parameter', 0]
    ])('should store a browser session cookie without an expiry when the expiry is %s', async (_, expiry) => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, expiry);

      expect(await storedCookie('authorization')).toMatchObject({ value: accessToken, path: '/', sameSite: 'strict', secure: true });
      expect((await await storedCookie('authorization')).isPersistent()).toEqual(false);
    });

    it('should store an empty cookie value when the token is undefined', async () => {
      userIdentityTokenStorageManager.setSessionToken(undefined, oneHourFromNow);

      expect(await storedCookie('authress-session')).toMatchObject({ value: '' });
    });

    it('should store an empty cookie value when the localhost redirect has no session_token query parameter', async () => {
      userIdentityTokenStorageManager.setSessionToken(new URLSearchParams('').get('session_token'), oneHourFromNow);

      expect(await storedCookie('authress-session')).toMatchObject({ value: '' });
    });

    it('should refuse to write the cookie when the expiry is not a valid date', async () => {
      expect(() => userIdentityTokenStorageManager.setAuthorizationToken(accessToken, new Date('not-a-date'))).toThrow(TypeError);
      expect(await storedCookie('authorization')).toBeUndefined();
    });

    it('should not write any cookie when running outside of a browser', async () => {
      vi.stubGlobal('window', undefined);

      expect(() => userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow)).not.toThrow();
      vi.unstubAllGlobals();
      expect(await storedCookie('authorization')).toBeUndefined();
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

    it('should no longer read back the access token once it is written with an already passed expiry', async () => {
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, oneHourFromNow);
      userIdentityTokenStorageManager.setAuthorizationToken(accessToken, new Date('2026-11-06T11:59:50.000Z'));

      expect(await storedCookie('authorization')).toBeUndefined();
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
