import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';

import { LoginClient } from '../src/index.js';
import windowManager from '../src/windowManager.js';

let windowManagerMock;

beforeEach(() => {
  // Use vi.mock to mock the module, or vi.spyOn to mock methods
  windowManagerMock = vi.spyOn(windowManager, 'onLoad').mockImplementation(() => {});
});
afterEach(() => {
  // Use vi.restoreAllMocks for cleanup
  vi.restoreAllMocks();
});

describe('index.js', () => {
  describe('LoginClient', () => {
    describe('constructor', () => {
      const tests = {};
      tests[Symbol.iterator] = function* () {
        yield {
          name: 'loginHost set correctly',
          url: 'https://login.test.com',
          expectedBaseUrl: 'https://login.test.com/api'
        };

        yield {
          name: 'loginHost set correctly from http',
          url: 'http://login.test.com',
          expectedBaseUrl: 'http://login.test.com/api'
        };

        yield {
          name: 'loginHost set correctly no scheme',
          url: 'login.test.com',
          expectedBaseUrl: 'https://login.test.com/api'
        };

        yield {
          name: 'loginHost set correctly with path',
          url: 'login.test.com/path',
          expectedBaseUrl: 'https://login.test.com/api'
        };

        yield {
          name: 'loginHost set with wrong scheme',
          url: 'https:/login.test.com/path',
          expectedBaseUrl: 'https://login.test.com/api'
        };

        yield {
          name: 'loginHost not set',
          url: null,
          expectedBaseUrl: 'https://login.test.com/api',
          expectedError: 'Missing required property "authressApiUrl" in LoginClient constructor. Custom Authress Domain Host is required.'
        };
      };
      
      for (let test of tests) {
        // eslint-disable-next-line no-loop-func
        it(test.name, () => {
          // Reset mock implementation for each test
          windowManagerMock.mockClear();
          
          if (test.expectedError) {
            // Use expect().toThrow() for expected errors
            expect(() => {
              new LoginClient({ authressApiUrl: test.url });
            }).toThrow(test.expectedError);
            
            // Verify onLoad was NOT called (0 times)
            expect(windowManagerMock).not.toHaveBeenCalled(); 
          } else {
            // Assert that the function does NOT throw
            const loginClient = new LoginClient({ authressApiUrl: test.url });
            
            // Assert Base URL
            expect(loginClient.httpClient.loginUrl).toEqual(test.expectedBaseUrl);
            
            // Verify onLoad was called exactly once
            expect(windowManagerMock).toHaveBeenCalledTimes(1);
          }
        });
      }
    });
  });

  describe('getMatchingDomainInfo()', () => {
    beforeEach(() => {
      // Restore onLoad mock for this describe block and spy on getCurrentLocation
      vi.restoreAllMocks(); 
    });

    it('Adjacent domain returns true', () => {
      const authressApiUrl = 'https://security.application.com';
      const loginClient = new LoginClient({ authressApiUrl, skipBackgroundCredentialsCheck: true });
      
      // Use vi.spyOn for mocking specific functions and mockImplementation for return value
      const getCurrentLocationMock = vi.spyOn(windowManager, 'getCurrentLocation').mockImplementation(() => ({
        protocol: 'https:',
        host: 'app.application.com'
      }));

      const result = loginClient.getMatchingDomainInfo(authressApiUrl);
      
      // Verify call count (Sinon expects.exactly(1) becomes Vitest's toHaveBeenCalledTimes(1))
      expect(getCurrentLocationMock).toHaveBeenCalledTimes(1);
      // Use toEqual for deep equality check (similar to Chai's to.eql)
      expect(result).toEqual(true); 
    });

    it('Top level domain returns true', () => {
      const authressApiUrl = 'https://security.application.com';
      const loginClient = new LoginClient({ authressApiUrl, skipBackgroundCredentialsCheck: true });
      
      const getCurrentLocationMock = vi.spyOn(windowManager, 'getCurrentLocation').mockImplementation(() => ({
        protocol: 'https:',
        host: 'application.com'
      }));

      const result = loginClient.getMatchingDomainInfo(authressApiUrl);
      
      expect(getCurrentLocationMock).toHaveBeenCalledTimes(1);
      expect(result).toEqual(true);
    });

    it('Cross domain returns false', () => {
      const authressApiUrl = 'https://security.application.com';
      const loginClient = new LoginClient({ authressApiUrl, skipBackgroundCredentialsCheck: true });
      
      const getCurrentLocationMock = vi.spyOn(windowManager, 'getCurrentLocation').mockImplementation(() => ({
        protocol: 'https:',
        host: 'app.cross-domain.com'
      }));

      const result = loginClient.getMatchingDomainInfo(authressApiUrl);
      
      expect(getCurrentLocationMock).toHaveBeenCalledTimes(1);
      expect(result).toEqual(false);
    });
  });
});