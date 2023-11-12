const { describe, it, beforeEach, afterEach } = require('mocha');
const sinon = require('sinon');
const { expect } = require('chai');

const { LoginClient } = require('../src/index');

let sandbox;
beforeEach(() => { sandbox = sinon.createSandbox(); });
afterEach(() => sandbox.restore());

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
          expectedBaseUrl: 'https://login.test.com/api'
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
          expectedError: 'Missing required property "authressLoginHostUrl" in LoginClient constructor. Custom Authress Domain Host is required.'
        };
      };
      for (let test of tests) {
        it(test.name, () => {
          try {
            const loginClient = new LoginClient({ authressLoginHostUrl: test.url, skipBackgroundCredentialsCheck: true });
            expect(loginClient.httpClient.loginUrl).to.eql(test.expectedBaseUrl);
            expect(test.expectedError).to.eql(undefined);
          } catch (error) {
            expect(error.message).to.eql(test.expectedError, `The test was not supposed to throw an error, but it did: ${error.message}`);
          }
        });
      }
    });
  });

  describe('getMatchingDomainInfo()', () => {
    it('Adjacent domain returns true', () => {
      const authressLoginHostUrl = 'https://security.application.com';
      const loginClient = new LoginClient({ authressLoginHostUrl, skipBackgroundCredentialsCheck: true });
      const window = {
        location: {
          protocol: 'https:',
          host: 'app.application.com'
        }
      };
      const result = loginClient.getMatchingDomainInfo(authressLoginHostUrl, window);
      expect(result).to.eql(true);
    });

    it('Top level domain returns true', () => {
      const authressLoginHostUrl = 'https://security.application.com';
      const loginClient = new LoginClient({ authressLoginHostUrl, skipBackgroundCredentialsCheck: true });
      const window = {
        location: {
          protocol: 'https:',
          host: 'application.com'
        }
      };
      const result = loginClient.getMatchingDomainInfo(authressLoginHostUrl, window);
      expect(result).to.eql(true);
    });

    it('Cross domain returns false', () => {
      const authressLoginHostUrl = 'https://security.application.com';
      const loginClient = new LoginClient({ authressLoginHostUrl, skipBackgroundCredentialsCheck: true });
      const window = {
        location: {
          protocol: 'https:',
          host: 'app.cross-domain.com'
        }
      };
      const result = loginClient.getMatchingDomainInfo(authressLoginHostUrl, window);
      expect(result).to.eql(false);
    });
  });
});

