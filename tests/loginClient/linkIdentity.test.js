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
    authenticationUrl: 'https://provider.example.com/link?request_id=link123',
    authenticationRequestId: 'req_link_12345',
    ...overrides
  }
});

beforeEach(() => {
  vi.spyOn(windowManager, 'onLoad').mockImplementation(() => {});
  vi.spyOn(windowManager, 'getCurrentLocation').mockImplementation(() => new URL('https://app.example.com'));
  vi.spyOn(windowManager, 'isLocalHost').mockReturnValue(false);

  loginClient = new LoginClient({ authressApiUrl: 'https://login.example.com', applicationId: 'app_test', skipBackgroundCredentialsCheck: true });

  // linkIdentity requires the user to be logged in
  vi.spyOn(loginClient, 'getUserIdentity').mockReturnValue({ sub: 'user_123', userId: 'user_123' });
  vi.spyOn(loginClient, 'ensureToken').mockResolvedValue('mock-access-token');

  httpPostSpy = vi.spyOn(loginClient.httpClient, 'post').mockResolvedValue(mockAuthResponse());
  loggerSpy = vi.spyOn(loginClient.logger, 'log').mockImplementation(() => {});
  assignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
  openSpy = vi.spyOn(windowManager, 'open').mockImplementation(() => ({ closed: false }));

  vi.spyOn(jwtManager, 'getAuthCodes').mockResolvedValue({ codeVerifier: 'verifier', codeChallenge: 'challenge' });
  vi.spyOn(jwtManager, 'calculateAntiAbuseHash').mockResolvedValue('hash');
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('loginClient.linkIdentity()', () => {
  describe('redirectOpenType validation', () => {
    it('throws for invalid string value', async () => {
      await expect(loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'invalid' }))
        .rejects.toMatchObject({ code: 'InvalidRedirectOpenType' });
    });

    it('does not throw for null (defaults to redirect)', async () => {
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: null });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('does not throw for undefined (defaults to redirect)', async () => {
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: undefined });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('does not make a network call when validation fails', async () => {
      await expect(loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'bad' })).rejects.toThrow();
      expect(httpPostSpy).not.toHaveBeenCalled();
    });
  });

  describe('redirect mode (default)', () => {
    it('calls windowManager.assign when redirectOpenType is absent', async () => {
      await loginClient.linkIdentity({ connectionId: 'con_1' });
      expect(assignSpy).toHaveBeenCalledWith('https://provider.example.com/link?request_id=link123');
      expect(openSpy).not.toHaveBeenCalled();
    });

    it('calls windowManager.assign when redirectOpenType is "redirect"', async () => {
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'redirect' });
      expect(assignSpy).toHaveBeenCalledWith('https://provider.example.com/link?request_id=link123');
    });

    it('returns response in redirect mode', async () => {
      const result = await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'redirect' });
      expect(result).toEqual({
        authenticationUrl: 'https://provider.example.com/link?request_id=link123',
        authenticationRequestId: 'req_link_12345'
      });
    });
  });

  describe('tab mode', () => {
    it('calls windowManager.open when redirectOpenType is "tab"', async () => {
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'tab' });
      expect(openSpy).toHaveBeenCalledWith('https://provider.example.com/link?request_id=link123', '_blank');
    });

    it('falls back to assign when open returns null (blocked popup)', async () => {
      openSpy.mockReturnValue(null);
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'tab' });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('falls back to assign when open returns object with closed=true', async () => {
      openSpy.mockReturnValue({ closed: true });
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'tab' });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('falls back to assign when open returns undefined', async () => {
      openSpy.mockReturnValue(undefined);
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'tab' });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('falls back to assign when open returns object with no closed property', async () => {
      openSpy.mockReturnValue({});
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'tab' });
      expect(assignSpy).toHaveBeenCalledTimes(1);
    });

    it('does not call assign when tab opens successfully', async () => {
      openSpy.mockReturnValue({ closed: false });
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'tab' });
      expect(assignSpy).not.toHaveBeenCalled();
    });
  });

  describe('client-managed mode', () => {
    it('does not call windowManager.assign', async () => {
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'client-managed' });
      expect(assignSpy).not.toHaveBeenCalled();
    });

    it('does not call windowManager.open', async () => {
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'client-managed' });
      expect(openSpy).not.toHaveBeenCalled();
    });

    it('returns authenticationUrl and authenticationRequestId', async () => {
      const result = await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'client-managed' });
      expect(result).toEqual({
        authenticationUrl: 'https://provider.example.com/link?request_id=link123',
        authenticationRequestId: 'req_link_12345'
      });
    });
  });

  describe('log line', () => {
    it('emits log with authenticationRequestId before navigation', async () => {
      const callOrder = [];
      loggerSpy.mockImplementation(() => callOrder.push('log'));
      assignSpy.mockImplementation(() => callOrder.push('assign'));

      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'redirect' });

      expect(loggerSpy).toHaveBeenCalledWith(expect.objectContaining({
        authenticationRequestId: 'req_link_12345'
      }));
      expect(callOrder.indexOf('log')).toBeLessThan(callOrder.indexOf('assign'));
    });

    it('emits log in client-managed mode', async () => {
      await loginClient.linkIdentity({ connectionId: 'con_1', redirectOpenType: 'client-managed' });
      expect(loggerSpy).toHaveBeenCalledWith(expect.objectContaining({
        authenticationRequestId: 'req_link_12345'
      }));
    });
  });
});
