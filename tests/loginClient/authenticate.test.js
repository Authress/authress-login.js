import { describe, it, afterEach, beforeEach, expect, vi } from 'vitest';

import { LoginClient } from '../../src/index.js';
import windowManager from '../../src/windowManager.js';
import jwtManager from '../../src/jwtManager.js';

let loginClient;
let httpPostSpy;
let loggerSpy;
let assignSpy;
let openSpy;

const mockAuthResponse = (overrides = {}) => ({
  data: {
    authenticationUrl: 'https://provider.example.com/authorize?request_id=abc123',
    authenticationRequestId: 'req_test_12345',
    enableCredentials: false,
    ...overrides
  }
});

beforeEach(() => {
  vi.spyOn(windowManager, 'onLoad').mockImplementation(() => {});
  vi.spyOn(windowManager, 'getCurrentLocation').mockImplementation(() => new URL('https://app.example.com'));

  loginClient = new LoginClient({ authressApiUrl: 'https://login.example.com', applicationId: 'app_test', skipBackgroundCredentialsCheck: true });

  httpPostSpy = vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue(mockAuthResponse());
  loggerSpy = vi.spyOn(loginClient.logger, 'log').mockImplementation(() => {});
  assignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
  openSpy = vi.spyOn(windowManager, 'open').mockImplementation(() => ({ closed: false }));

  vi.spyOn(jwtManager, 'getAuthCodes').mockResolvedValue({ codeVerifier: 'verifier', codeChallenge: 'challenge' });
  vi.spyOn(jwtManager, 'calculateAntiAbuseHash').mockResolvedValue('hash');

  // Mock localStorage
  const store = {};
  vi.stubGlobal('localStorage', {
    getItem: vi.fn(k => store[k] || null),
    setItem: vi.fn((k, v) => { store[k] = v; }),
    removeItem: vi.fn(k => { delete store[k]; })
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('loginClient.authenticate()', () => {
  describe('redirectOpenType validation', () => {
    it('throws for invalid string value', async () => {
      await expect(loginClient.authenticate({ redirectOpenType: 'invalid-value' }))
        .rejects.toMatchObject({ code: 'InvalidRedirectOpenType' });
    });

    it('throws with descriptive message for invalid value', async () => {
      await expect(loginClient.authenticate({ redirectOpenType: 'popup' }))
        .rejects.toThrow('The redirectOpenType "popup" is not valid. Must be one of: redirect, tab, client-managed');
    });

    it('does not throw for null (defaults to redirect)', async () => {
      await loginClient.authenticate({ redirectOpenType: null });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('does not throw for undefined (defaults to redirect)', async () => {
      await loginClient.authenticate({ redirectOpenType: undefined });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('does not make a network call when validation fails', async () => {
      await expect(loginClient.authenticate({ redirectOpenType: 'bad' })).rejects.toThrow();
      expect(httpPostSpy).not.toHaveBeenCalled();
    });
  });

  describe('redirect mode (default)', () => {
    it('calls windowManager.assign when redirectOpenType is absent', async () => {
      await loginClient.authenticate({});
      expect(assignSpy).toHaveBeenCalledWith('https://provider.example.com/authorize?request_id=abc123');
      expect(openSpy).not.toHaveBeenCalled();
    });

    it('calls windowManager.assign when redirectOpenType is "redirect"', async () => {
      await loginClient.authenticate({ redirectOpenType: 'redirect' });
      expect(assignSpy).toHaveBeenCalledWith('https://provider.example.com/authorize?request_id=abc123');
      expect(openSpy).not.toHaveBeenCalled();
    });

    it('returns response in redirect mode', async () => {
      const result = await loginClient.authenticate({ redirectOpenType: 'redirect' });
      expect(result).toEqual({
        authenticationUrl: 'https://provider.example.com/authorize?request_id=abc123',
        authenticationRequestId: 'req_test_12345'
      });
    });
  });

  describe('tab mode', () => {
    it('calls windowManager.open when redirectOpenType is "tab"', async () => {
      await loginClient.authenticate({ redirectOpenType: 'tab' });
      expect(openSpy).toHaveBeenCalledWith('https://provider.example.com/authorize?request_id=abc123', '_blank');
    });

    it('falls back to assign when open returns null (blocked popup)', async () => {
      openSpy.mockReturnValue(null);
      await loginClient.authenticate({ redirectOpenType: 'tab' });
      expect(openSpy).toHaveBeenCalledTimes(1);
      expect(assignSpy).toHaveBeenCalledWith('https://provider.example.com/authorize?request_id=abc123');
    });

    it('falls back to assign when open returns object with closed=true', async () => {
      openSpy.mockReturnValue({ closed: true });
      await loginClient.authenticate({ redirectOpenType: 'tab' });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('falls back to assign when open returns object with closed=undefined', async () => {
      openSpy.mockReturnValue({ closed: undefined });
      await loginClient.authenticate({ redirectOpenType: 'tab' });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('falls back to assign when open returns undefined', async () => {
      openSpy.mockReturnValue(undefined);
      await loginClient.authenticate({ redirectOpenType: 'tab' });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('falls back to assign when open returns object with no closed property', async () => {
      openSpy.mockReturnValue({});
      await loginClient.authenticate({ redirectOpenType: 'tab' });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('does not call assign when tab opens successfully', async () => {
      openSpy.mockReturnValue({ closed: false });
      await loginClient.authenticate({ redirectOpenType: 'tab' });
      expect(assignSpy).not.toHaveBeenCalled();
    });

    it('returns response in tab mode', async () => {
      const result = await loginClient.authenticate({ redirectOpenType: 'tab' });
      expect(result).toEqual({
        authenticationUrl: 'https://provider.example.com/authorize?request_id=abc123',
        authenticationRequestId: 'req_test_12345'
      });
    });
  });

  describe('client-managed mode', () => {
    it('does not call windowManager.assign', async () => {
      await loginClient.authenticate({ redirectOpenType: 'client-managed' });
      expect(assignSpy).not.toHaveBeenCalled();
    });

    it('does not call windowManager.open', async () => {
      await loginClient.authenticate({ redirectOpenType: 'client-managed' });
      expect(openSpy).not.toHaveBeenCalled();
    });

    it('returns authenticationUrl and authenticationRequestId', async () => {
      const result = await loginClient.authenticate({ redirectOpenType: 'client-managed' });
      expect(result).toEqual({
        authenticationUrl: 'https://provider.example.com/authorize?request_id=abc123',
        authenticationRequestId: 'req_test_12345'
      });
    });

    it('returns the exact values from the server response unmodified', async () => {
      const customUrl = 'https://idp.custom.org/login?session=xyz&foo=bar';
      const customId = 'req_custom_99999';
      httpPostSpy.mockResolvedValue(mockAuthResponse({ authenticationUrl: customUrl, authenticationRequestId: customId }));

      const result = await loginClient.authenticate({ redirectOpenType: 'client-managed' });
      expect(result.authenticationUrl).toBe(customUrl);
      expect(result.authenticationRequestId).toBe(customId);
    });

    it('stores authentication request state in localStorage', async () => {
      await loginClient.authenticate({ redirectOpenType: 'client-managed' });
      expect(localStorage.setItem).toHaveBeenCalledTimes(1);
      const stored = JSON.parse(localStorage.setItem.mock.calls[0][1]);
      expect(stored.nonce).toBe('req_test_12345');
    });
  });

  describe('openType deprecated fallback', () => {
    it('uses openType when redirectOpenType is absent', async () => {
      await loginClient.authenticate({ openType: 'tab' });
      expect(openSpy).toHaveBeenCalledTimes(1);
    });

    it('redirectOpenType takes precedence over openType', async () => {
      await loginClient.authenticate({ redirectOpenType: 'redirect', openType: 'tab' });
      expect(assignSpy).toHaveBeenCalledTimes(1);
      expect(openSpy).not.toHaveBeenCalled();
    });

    it('redirectOpenType client-managed wins over openType tab', async () => {
      const result = await loginClient.authenticate({ redirectOpenType: 'client-managed', openType: 'tab' });
      expect(result).toEqual({
        authenticationUrl: 'https://provider.example.com/authorize?request_id=abc123',
        authenticationRequestId: 'req_test_12345'
      });
      expect(assignSpy).not.toHaveBeenCalled();
      expect(openSpy).not.toHaveBeenCalled();
    });
  });

  describe('log line', () => {
    it('emits log with correct title and authenticationRequestId in redirect mode', async () => {
      await loginClient.authenticate({ redirectOpenType: 'redirect' });
      expect(loggerSpy).toHaveBeenCalledWith(expect.objectContaining({
        title: '[Authress Login SDK] User Authentication Requested',
        authenticationRequestId: 'req_test_12345'
      }));
    });

    it('emits log exactly once per authenticate call', async () => {
      await loginClient.authenticate({ redirectOpenType: 'redirect' });
      const logCalls = loggerSpy.mock.calls.filter(c => c[0]?.title === '[Authress Login SDK] User Authentication Requested');
      expect(logCalls).toHaveLength(1);
    });

    it('emits log in client-managed mode', async () => {
      await loginClient.authenticate({ redirectOpenType: 'client-managed' });
      expect(loggerSpy).toHaveBeenCalledWith(expect.objectContaining({
        title: '[Authress Login SDK] User Authentication Requested',
        authenticationRequestId: 'req_test_12345'
      }));
    });

    it('emits log in tab mode', async () => {
      await loginClient.authenticate({ redirectOpenType: 'tab' });
      expect(loggerSpy).toHaveBeenCalledWith(expect.objectContaining({
        title: '[Authress Login SDK] User Authentication Requested',
        authenticationRequestId: 'req_test_12345'
      }));
    });

    it('emits log before windowManager.assign (ordering)', async () => {
      const callOrder = [];
      loggerSpy.mockImplementation(() => callOrder.push('log'));
      assignSpy.mockImplementation(() => callOrder.push('assign'));

      await loginClient.authenticate({ redirectOpenType: 'redirect' });
      expect(callOrder.indexOf('log')).toBeLessThan(callOrder.indexOf('assign'));
    });

    it('emits log with empty string when authenticationRequestId is missing', async () => {
      httpPostSpy.mockResolvedValue(mockAuthResponse({ authenticationRequestId: undefined }));
      await loginClient.authenticate({ redirectOpenType: 'client-managed' });
      expect(loggerSpy).toHaveBeenCalledWith(expect.objectContaining({
        title: '[Authress Login SDK] User Authentication Requested',
        authenticationRequestId: ''
      }));
    });
  });

  describe('custom-login-screen branch', () => {
    it('returns response when authenticationUrl hostname matches current location', async () => {
      httpPostSpy.mockResolvedValue(mockAuthResponse({ authenticationUrl: 'https://app.example.com/callback' }));
      const result = await loginClient.authenticate({});
      expect(result).toEqual({
        authenticationUrl: 'https://app.example.com/callback',
        authenticationRequestId: 'req_test_12345'
      });
      expect(assignSpy).not.toHaveBeenCalled();
    });

    it('emits log line in custom-login-screen branch', async () => {
      httpPostSpy.mockResolvedValue(mockAuthResponse({ authenticationUrl: 'https://app.example.com/callback' }));
      await loginClient.authenticate({});
      expect(loggerSpy).toHaveBeenCalledWith(expect.objectContaining({
        title: '[Authress Login SDK] User Authentication Requested',
        authenticationRequestId: 'req_test_12345'
      }));
    });
  });
});
