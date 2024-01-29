const { describe, it, beforeEach, afterEach } = require('mocha');
const sinon = require('sinon');
const { expect } = require('chai');

const { LoginClient } = require('../src/index');
const windowManager = require('../src/windowManager');

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
          const windowManagerMock = sandbox.mock(windowManager);
          windowManagerMock.expects('onLoad').exactly(test.expectedError ? 0 : 1);

          try {
            const loginClient = new LoginClient({ authressApiUrl: test.url });
            expect(loginClient.httpClient.loginUrl).to.eql(test.expectedBaseUrl);
            expect(test.expectedError).to.eql(undefined);
          } catch (error) {
            expect(error.message).to.eql(test.expectedError, `The test was not supposed to throw an error, but it did: ${error.message}`);
          }

          windowManagerMock.verify();
        });
      }
    });
  });

  describe('getMatchingDomainInfo()', () => {
    it('Adjacent domain returns true', () => {
      const authressApiUrl = 'https://security.application.com';
      const loginClient = new LoginClient({ authressApiUrl, skipBackgroundCredentialsCheck: true });
      
      const windowManagerMock = sandbox.mock(windowManager);
      windowManagerMock.expects('onLoad').exactly(0);
      windowManagerMock.expects('getCurrentLocation').exactly(1).returns({
        protocol: 'https:',
        host: 'app.application.com'
      });
      const result = loginClient.getMatchingDomainInfo(authressApiUrl);
      windowManagerMock.verify();
      expect(result).to.eql(true);
    });

    it('Top level domain returns true', () => {
      const authressApiUrl = 'https://security.application.com';
      const loginClient = new LoginClient({ authressApiUrl, skipBackgroundCredentialsCheck: true });
      
      const windowManagerMock = sandbox.mock(windowManager);
      windowManagerMock.expects('onLoad').exactly(0);
      windowManagerMock.expects('getCurrentLocation').exactly(1).returns({
        protocol: 'https:',
        host: 'application.com'
      });
      const result = loginClient.getMatchingDomainInfo(authressApiUrl);
      windowManagerMock.verify();
      expect(result).to.eql(true);
    });

    it('Cross domain returns false', () => {
      const authressApiUrl = 'https://security.application.com';
      const loginClient = new LoginClient({ authressApiUrl, skipBackgroundCredentialsCheck: true });
      
      const windowManagerMock = sandbox.mock(windowManager);
      windowManagerMock.expects('onLoad').exactly(0);
      windowManagerMock.expects('getCurrentLocation').exactly(1).returns({
        protocol: 'https:',
        host: 'app.cross-domain.com'
      });
      const result = loginClient.getMatchingDomainInfo(authressApiUrl);
      windowManagerMock.verify();
      expect(result).to.eql(false);
    });
  });
});

