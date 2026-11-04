import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

import { LoginClient, PersistenceType } from '../../src/index.js';
import windowManager from '../../src/windowManager.js';
import userIdentityTokenStorageManager from '../../src/userIdentityTokenStorageManager.js';

let localStorageItems;

beforeEach(() => {
  localStorageItems = {};
  vi.stubGlobal('window', { location: new URL('https://app.example.com') });
  vi.stubGlobal('localStorage', {
    getItem: key => localStorageItems[key] ?? null,
    setItem(key, value) { localStorageItems[key] = value; },
    removeItem(key) { delete localStorageItems[key]; }
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  userIdentityTokenStorageManager.persistenceType = PersistenceType.Cookie;
});

function createDocumentRecordingCookieWrites() {
  const cookieWrites = [];
  const fakeDocument = {};
  Object.defineProperty(fakeDocument, 'cookie', { set(value) { cookieWrites.push(value); }, get: () => '' });
  vi.stubGlobal('document', fakeDocument);
  vi.spyOn(windowManager, 'getDocument').mockReturnValue(fakeDocument);
  return cookieWrites;
}

function createLoginClient(persistenceType) {
  return new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true, persistenceType });
}

const oneMinuteFromNow = () => new Date(Date.now() + 60000);

describe('loginClient.js', () => {
  describe('persistenceType', () => {
    it('should persist the authorization and session tokens as cookies by default', () => {
      const cookieWrites = createDocumentRecordingCookieWrites();
      expect(createLoginClient(undefined)).toBeDefined();

      userIdentityTokenStorageManager.setAuthorizationToken('access-token', oneMinuteFromNow());
      userIdentityTokenStorageManager.setSessionToken('session-token', oneMinuteFromNow());

      expect(cookieWrites).toHaveLength(2);
      expect(cookieWrites[0]).toMatch(/^authorization=access-token;/);
      expect(cookieWrites[1]).toMatch(/^authress-session=session-token;/);
      expect(localStorageItems.AuthressPersistedTokens).toBeUndefined();
    });

    it('should persist the tokens as cookies when persistenceType is null', () => {
      const cookieWrites = createDocumentRecordingCookieWrites();
      expect(createLoginClient(null)).toBeDefined();

      userIdentityTokenStorageManager.setAuthorizationToken('access-token', oneMinuteFromNow());

      expect(cookieWrites).toHaveLength(1);
    });

    it('should persist the tokens to localStorage instead of cookies when set to LOCAL_STORAGE', () => {
      const cookieWrites = createDocumentRecordingCookieWrites();
      expect(createLoginClient(PersistenceType.LocalStorage)).toBeDefined();

      userIdentityTokenStorageManager.setAuthorizationToken('access-token', oneMinuteFromNow());
      userIdentityTokenStorageManager.setSessionToken('session-token', oneMinuteFromNow());

      expect(cookieWrites).toHaveLength(0);
      expect(Object.keys(JSON.parse(localStorageItems.AuthressPersistedTokens))).toEqual(['authorization', 'authress-session']);
    });

    it('should read back the authorization token from localStorage when set to LOCAL_STORAGE', () => {
      createDocumentRecordingCookieWrites();
      expect(createLoginClient(PersistenceType.LocalStorage)).toBeDefined();

      userIdentityTokenStorageManager.setAuthorizationToken('access-token', oneMinuteFromNow());

      expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual(['access-token']);
    });

    it('should not read back an expired authorization token from localStorage', () => {
      createDocumentRecordingCookieWrites();
      expect(createLoginClient(PersistenceType.LocalStorage)).toBeDefined();

      userIdentityTokenStorageManager.setAuthorizationToken('access-token', new Date(Date.now() - 1000));

      expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([]);
    });

    it('should remove the localStorage tokens when the user data is cleared', () => {
      createDocumentRecordingCookieWrites();
      expect(createLoginClient(PersistenceType.LocalStorage)).toBeDefined();
      userIdentityTokenStorageManager.setAuthorizationToken('access-token', oneMinuteFromNow());

      userIdentityTokenStorageManager.clear();

      expect(userIdentityTokenStorageManager.getAuthorizationTokens()).toEqual([]);
    });

    it('should mark the cookies secure only when running over https', () => {
      const cookieWrites = createDocumentRecordingCookieWrites();
      vi.spyOn(windowManager, 'getCurrentLocation').mockReturnValueOnce(new URL('https://app.example.com')).mockReturnValueOnce(new URL('http://app.example.com'));

      userIdentityTokenStorageManager.setAuthorizationToken('access-token', oneMinuteFromNow());
      userIdentityTokenStorageManager.setAuthorizationToken('access-token', oneMinuteFromNow());

      expect(cookieWrites[0]).toMatch(/; Secure/);
      expect(cookieWrites[1]).not.toMatch(/; Secure/);
    });

    it('should reject an unknown persistence type', () => {
      expect(() => createLoginClient('NONE')).toThrow(expect.objectContaining({ code: 'InvalidPersistenceType' }));
    });
  });
});
