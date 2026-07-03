import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

import { LoginClient } from '../../src/index.js';
import windowManager from '../../src/windowManager.js';
import HttpClient from '../../src/httpClient.js';
import jwtManager from '../../src/jwtManager.js';
import userIdentityTokenStorageManager from '../../src/userIdentityTokenStorageManager.js';

const authResponseData = {
  authenticationUrl: 'https://login.authress.io/authenticate',
  authenticationRequestId: 'req_test123'
};

function createLoginClient() {
  const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });
  vi.spyOn(loginClient, 'userSessionExists').mockResolvedValue(false);
  return loginClient;
}

beforeEach(() => {
  vi.useFakeTimers();
  globalThis.localStorage = { getItem: vi.fn(), setItem: vi.fn(), removeItem: vi.fn(), clear: vi.fn() };
  vi.spyOn(windowManager, 'getCurrentLocation').mockReturnValue(new URL('https://app.example.com'));
  vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
  vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});
  vi.spyOn(jwtManager, 'getAuthCodes').mockResolvedValue({ codeVerifier: 'test-verifier', codeChallenge: 'test-challenge' });
  vi.spyOn(jwtManager, 'calculateAntiAbuseHash').mockResolvedValue('test-hash');
  vi.spyOn(HttpClient.prototype, 'post').mockResolvedValue({ data: authResponseData });
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  delete globalThis.localStorage;
});

describe('loginClient.js', () => {
  describe('authenticate', () => {
    it('should call onStartAuthentication with the response before redirecting', async () => {
      const callOrder = [];
      const onStartAuthentication = vi.fn().mockImplementation(() => { callOrder.push('onStartAuthentication'); });
      windowManager.assign.mockImplementation(() => { callOrder.push('assign'); });

      const loginClient = createLoginClient();
      const authenticatePromise = loginClient.authenticate({ connectionId: 'test-connection', onStartAuthentication });
      await vi.runAllTimersAsync();
      await authenticatePromise;

      expect(onStartAuthentication).toHaveBeenCalledOnce();
      expect(onStartAuthentication).toHaveBeenCalledWith({
        authenticationUrl: authResponseData.authenticationUrl,
        authenticationRequestId: authResponseData.authenticationRequestId
      });
      expect(windowManager.assign).toHaveBeenCalledOnce();
      expect(callOrder).toEqual(['onStartAuthentication', 'assign']);
    });

    it('should await an async onStartAuthentication before redirecting', async () => {
      let callbackResolved = false;
      const callOrder = [];
      const onStartAuthentication = vi.fn().mockImplementation(() => {
        return new Promise(resolve => {
          setTimeout(() => { callbackResolved = true; callOrder.push('onStartAuthentication'); resolve(); }, 10);
        });
      });
      windowManager.assign.mockImplementation(() => { callOrder.push('assign'); });

      const loginClient = createLoginClient();
      const authenticatePromise = loginClient.authenticate({ connectionId: 'test-connection', onStartAuthentication });
      await vi.runAllTimersAsync();
      await authenticatePromise;

      expect(callbackResolved).toBe(true);
      expect(callOrder).toEqual(['onStartAuthentication', 'assign']);
    });

    it('should redirect without calling onStartAuthentication when it is not provided', async () => {
      const loginClient = createLoginClient();
      const authenticatePromise = loginClient.authenticate({ connectionId: 'test-connection' });
      await vi.runAllTimersAsync();
      await authenticatePromise;

      expect(windowManager.assign).toHaveBeenCalledOnce();
      expect(windowManager.assign).toHaveBeenCalledWith(authResponseData.authenticationUrl);
    });

    it('should propagate errors thrown by onStartAuthentication', async () => {
      const onStartAuthentication = vi.fn().mockRejectedValue(new Error('Logging failed'));

      const loginClient = createLoginClient();
      await expect(loginClient.authenticate({
        connectionId: 'test-connection',
        onStartAuthentication
      })).rejects.toThrow('Logging failed');

      expect(windowManager.assign).not.toHaveBeenCalled();
    });
  });

  describe('linkIdentity', () => {
    it('should call onStartAuthentication with the response before redirecting', async () => {
      const callOrder = [];
      const onStartAuthentication = vi.fn().mockImplementation(() => { callOrder.push('onStartAuthentication'); });
      windowManager.assign.mockImplementation(() => { callOrder.push('assign'); });

      const loginClient = createLoginClient();
      vi.spyOn(loginClient, 'getUserIdentity').mockReturnValue({ sub: 'user-123' });
      vi.spyOn(loginClient, 'ensureToken').mockResolvedValue('test-token');

      const linkPromise = loginClient.linkIdentity({ connectionId: 'test-connection', onStartAuthentication });
      await vi.runAllTimersAsync();
      await linkPromise;

      expect(onStartAuthentication).toHaveBeenCalledOnce();
      expect(onStartAuthentication).toHaveBeenCalledWith({
        authenticationUrl: authResponseData.authenticationUrl,
        authenticationRequestId: authResponseData.authenticationRequestId
      });
      expect(callOrder).toEqual(['onStartAuthentication', 'assign']);
    });
  });
});
