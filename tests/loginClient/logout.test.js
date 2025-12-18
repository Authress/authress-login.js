import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

import { LoginClient } from '../../src/index.js';
import windowManager from '../../src/windowManager.js';
import userIdentityTokenStorageManager from '../../src/userIdentityTokenStorageManager.js';
import httpClient from '../../src/httpClient.js';

let requestedRedirectUrl = 'https://valid-redirect.url';

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('loginClient.js', () => {
  describe('logout', () => {
    it('should clear the user identity token storage and sanitize query parameters', async () => {
      const setTimeoutSpy = vi.spyOn(global, 'setTimeout');

      // Spy on clear() and assert call expectations
      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});

      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });
      // Stub the internal method
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});

      const logoutAsync = loginClient.logout(requestedRedirectUrl);
      
      vi.runAllTimers();
      await logoutAsync;

      expect(setTimeoutSpy).toHaveBeenCalledOnce();
      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
    });

    it('should attempt to delete the session if credentials are enabled', async () => {
      const setTimeoutSpy = vi.spyOn(global, 'setTimeout');
      
      // Spy on clear()
      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});
      
      // Mock the HTTP client prototype delete method
      const deleteSpy = vi.spyOn(httpClient.prototype, 'delete').mockResolvedValue(undefined);
      
      // Mock windowManager.assign
      const assignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
      
      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});

      loginClient.enableCredentials = true;
      await loginClient.logout(requestedRedirectUrl);

      expect(setTimeoutSpy).not.toHaveBeenCalled();
      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
      
      // Verify delete call arguments
      expect(deleteSpy).toHaveBeenCalledOnce();
      expect(deleteSpy).toHaveBeenCalledWith('/session', true);
      
      // Verify assign call arguments
      expect(assignSpy).toHaveBeenCalledOnce();
      expect(assignSpy).toHaveBeenCalledWith(requestedRedirectUrl);
    });

    it('should attempt to delete the session if credentials are enabled and work for relative urls as well', async () => {
      const setTimeoutSpy = vi.spyOn(global, 'setTimeout');
      
      const relativeUrl = '/relative-url';

      const deleteSpy = vi.spyOn(httpClient.prototype, 'delete').mockResolvedValue(undefined);
      const assignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});

      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});

      loginClient.enableCredentials = true;
      const logoutAsync = loginClient.logout(relativeUrl);

      expect(setTimeoutSpy).not.toHaveBeenCalled();
      await logoutAsync;

      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
      
      expect(deleteSpy).toHaveBeenCalledOnce();
      expect(deleteSpy).toHaveBeenCalledWith('/session', true);
      
      expect(assignSpy).toHaveBeenCalledOnce();
      expect(assignSpy).toHaveBeenCalledWith(relativeUrl);
    });

    it('should attempt to delete the session if credentials are enabled and work for no redirect url presented', async () => {
      const setTimeoutSpy = vi.spyOn(global, 'setTimeout');

      const relativeUrl = null;

      const deleteSpy = vi.spyOn(httpClient.prototype, 'delete').mockResolvedValue(undefined);
      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});
      const assignSpy = vi.spyOn(windowManager, 'assign'); // Should not be called

      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});

      loginClient.enableCredentials = true;
      await loginClient.logout(relativeUrl);

      expect(setTimeoutSpy).not.toHaveBeenCalled();
      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
      
      expect(deleteSpy).toHaveBeenCalledOnce();
      expect(deleteSpy).toHaveBeenCalledWith('/session', true);
      
      expect(assignSpy).not.toHaveBeenCalled();
    });

    it('should assign fullLogoutUrl if session deletion fails', async () => {
      const setTimeoutSpy = vi.spyOn(global, 'setTimeout');

      const fullLogoutUrl = 'https://auth.example.com/logout?redirect_uri=https%3A%2F%2Fvalid-redirect.url&client_id=app_id';

      // Mock delete to reject
      const deleteSpy = vi.spyOn(httpClient.prototype, 'delete').mockRejectedValue(new Error('Failed to delete session'));

      const assignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
      const getCurrentLocationSpy = vi.spyOn(windowManager, 'getCurrentLocation').mockReturnValue({ href: 'https://current.location' });
      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});

      loginClient.enableCredentials = true;
      const logoutAsync = loginClient.logout(requestedRedirectUrl);

      // Pass control over the event loop back to the logoutAsync call so that it can actually hit the set timeout, and once we hit the timeout, then we can await logoutAsync, and assert the rest of the test.
      await Promise.resolve();
      vi.runAllTimers();
      await logoutAsync;

      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
      expect(deleteSpy).toHaveBeenCalledOnce();
      expect(getCurrentLocationSpy).toHaveBeenCalled();
      expect(setTimeoutSpy).toHaveBeenCalledOnce();
      expect(assignSpy).toHaveBeenCalledOnce();
      expect(assignSpy).toHaveBeenCalledWith(fullLogoutUrl);
    });

    it('should assign the fullLogoutUrl with redirect_uri and client_id when credentials are not enabled', async () => {
      const setTimeoutSpy = vi.spyOn(global, 'setTimeout');

      const fullLogoutUrl = 'https://auth.example.com/logout?redirect_uri=https%3A%2F%2Fvalid-redirect.url&client_id=app_id';
      
      const assignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
      const getCurrentLocationSpy = vi.spyOn(windowManager, 'getCurrentLocation').mockReturnValue({ href: 'https://valid-redirect.url' });

      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});

      const logoutAsync = loginClient.logout(requestedRedirectUrl);
      
      vi.runAllTimers();
      await logoutAsync;
      expect(setTimeoutSpy).toHaveBeenCalledOnce();
      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
      
      expect(assignSpy).toHaveBeenCalledOnce();
      expect(assignSpy).toHaveBeenCalledWith(fullLogoutUrl);
      expect(getCurrentLocationSpy).toHaveBeenCalled();
    });

    it('should handle relative requestedRedirectUrl and resolve using current location as /', async () => {
      const setTimeoutSpy = vi.spyOn(global, 'setTimeout');

      const relativeUrl = '/';

      const windowManagerAssignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
      const windowManagerLocationSpy = vi.spyOn(windowManager, 'getCurrentLocation').mockReturnValue({ href: 'https://current.location' });

      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});

      const logoutAsync = loginClient.logout(relativeUrl);

      const expectedUrl = 'https://auth.example.com/logout?redirect_uri=https%3A%2F%2Fcurrent.location%2F&client_id=app_id';
      
      vi.runAllTimers();
      await logoutAsync;
      expect(setTimeoutSpy).toHaveBeenCalledOnce();

      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
      
      // Should be called twice by the implementation to resolve the relative URL
      expect(windowManagerLocationSpy).toHaveBeenCalledTimes(2);
      expect(windowManagerAssignSpy).toHaveBeenCalledOnce();
      expect(windowManagerAssignSpy).toHaveBeenCalledWith(expectedUrl);
    });

    it('should handle relative requestedRedirectUrl and resolve using current location as /relative-url', async () => {
      const setTimeoutSpy = vi.spyOn(global, 'setTimeout');

      const relativeUrl = '/relative-url';
      
      const windowManagerAssignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
      const windowManagerLocationSpy = vi.spyOn(windowManager, 'getCurrentLocation').mockReturnValue({ href: 'https://current.location' });

      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});
      
      const logoutAsync = loginClient.logout(relativeUrl);

      const expectedUrl = 'https://auth.example.com/logout?redirect_uri=https%3A%2F%2Fcurrent.location%2Frelative-url&client_id=app_id';
      
      vi.runAllTimers();
      await logoutAsync;
      expect(setTimeoutSpy).toHaveBeenCalledOnce();

      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
      
      expect(windowManagerLocationSpy).toHaveBeenCalledTimes(2);
      expect(windowManagerAssignSpy).toHaveBeenCalledOnce();
      expect(windowManagerAssignSpy).toHaveBeenCalledWith(expectedUrl);
    });

    it('should set lastSessionCheck to 0 after logging out', async () => {
      const setTimeoutSpy = vi.spyOn(global, 'setTimeout');
      const assignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
      
      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});

      loginClient.lastSessionCheck = 12345;
      const logoutAsync = loginClient.logout(requestedRedirectUrl);
      vi.runAllTimers();
      await logoutAsync;

      expect(setTimeoutSpy).toHaveBeenCalledOnce();
      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
      
      // Assert property change
      expect(loginClient.lastSessionCheck).toEqual(0);
      
      expect(assignSpy).toHaveBeenCalledOnce();
    });

    it('should wait for 500ms after logging out', async () => {
      const assignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});

      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});

      const logoutPromise = loginClient.logout(requestedRedirectUrl);
      
      // Advance time by 500ms
      vi.advanceTimersByTime(500);
      
      // Now the setTimeout callback should have executed
      await logoutPromise;

      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
      expect(assignSpy).toHaveBeenCalledOnce();
    });

    it('Prevent returning before delete session is finished. If someone does not want to wait for it, then they should not await. If we want to make it easier for users, then we would need to keep track of the state in a cookie', async () => {
      let deleteResolved = false;
      let logoutReturned = false;

      // Create a promise that we control
      const deletePromiseBlockTime = 10000;
      const deletePromise = new Promise(resolve => {
        setTimeout(() => { deleteResolved = true; resolve(); }, deletePromiseBlockTime);
      });

      const deleteSpy = vi.spyOn(httpClient.prototype, 'delete').mockReturnValue(deletePromise);
      const assignSpy = vi.spyOn(windowManager, 'assign').mockImplementation(() => {});
      const clearSpy = vi.spyOn(userIdentityTokenStorageManager, 'clear').mockImplementation(() => {});

      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = vi.spyOn(loginClient, 'sanitizeQueryParameters').mockImplementation(() => {});

      loginClient.enableCredentials = true;

      // Start the logout process
      const logoutPromise = loginClient.logout(null).then(() => {
        logoutReturned = true;
      });

      // At this point, delete should have been called but not resolved
      expect(deleteSpy).toHaveBeenCalledOnce();
      expect(deleteResolved).toBe(false);
      expect(logoutReturned).toBe(false);

      // Advance timers to ensure that logout has not called
      vi.advanceTimersByTime(deletePromiseBlockTime / 2);
  
      // Give the event loop a chance to process any resolved promises
      await Promise.resolve();
  
      // CRITICAL: logout should NOT have returned yet because delete hasn't resolved
      expect(deleteResolved).toBe(false);
      expect(logoutReturned).toBe(false);

      // Advance timers to allow the delete to resolve
      vi.advanceTimersByTime(deletePromiseBlockTime / 2);
  
      // Wait for the logout to complete
      await logoutPromise;

      // Verify that delete was resolved before logout returned
      expect(deleteResolved).toBe(true);
      expect(logoutReturned).toBe(true);
  
      expect(sanitizeQueryParametersStub).toHaveBeenCalledOnce();
      expect(clearSpy).toHaveBeenCalledOnce();
      expect(assignSpy).not.toHaveBeenCalled();
    });
  });
});
