import { describe, it, afterEach, expect, vi } from 'vitest';

import { LoginClient } from '../../src/index.js';
import windowManager from '../../src/windowManager.js';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('loginClient.js', () => {
  describe('sanitizeQueryParameters', () => {
    it('removes auth-related query parameters from the URL', () => {
      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });

      vi.spyOn(windowManager, 'getCurrentLocation').mockImplementation(() =>
        new URL('https://app.example.com/page?nonce=abc&iss=https://auth.example.com&code=xyz&keep=this')
      );

      const replaceStateSpy = vi.fn();
      vi.stubGlobal('history', { state: null, replaceState: replaceStateSpy });

      loginClient.sanitizeQueryParameters();

      expect(replaceStateSpy).toHaveBeenCalledTimes(1);
      const [, , url] = replaceStateSpy.mock.calls[0];
      const resultUrl = new URL(url);
      expect(resultUrl.searchParams.has('nonce')).toBe(false);
      expect(resultUrl.searchParams.has('iss')).toBe(false);
      expect(resultUrl.searchParams.has('code')).toBe(false);
      expect(resultUrl.searchParams.get('keep')).toBe('this');
    });

    it('preserves existing history.state when replacing URL', () => {
      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });

      vi.spyOn(windowManager, 'getCurrentLocation').mockImplementation(() =>
        new URL('https://app.example.com/?code=abc')
      );

      const routerState = { __TSR_key: 'abc', idx: 3 };
      const replaceStateSpy = vi.fn();
      vi.stubGlobal('history', { state: routerState, replaceState: replaceStateSpy });

      loginClient.sanitizeQueryParameters();

      expect(replaceStateSpy).toHaveBeenCalledTimes(1);
      const [stateArg] = replaceStateSpy.mock.calls[0];
      expect(stateArg).toBe(routerState);
    });

    it('passes null state when history.state is null', () => {
      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });

      vi.spyOn(windowManager, 'getCurrentLocation').mockImplementation(() =>
        new URL('https://app.example.com/?code=abc')
      );

      const replaceStateSpy = vi.fn();
      vi.stubGlobal('history', { state: null, replaceState: replaceStateSpy });

      loginClient.sanitizeQueryParameters();

      expect(replaceStateSpy).toHaveBeenCalledTimes(1);
      const [stateArg] = replaceStateSpy.mock.calls[0];
      expect(stateArg).toBeNull();
    });
  });
});
