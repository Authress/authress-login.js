const { describe, it, beforeEach, afterEach } = require('mocha');
const sinon = require('sinon');
const { expect } = require('chai');

const { LoginClient } = require('../src/index');
const windowManager = require('../src/windowManager');
const { sanitizeUrl } = require('../src/util');

let sandbox;
beforeEach(() => { sandbox = sinon.createSandbox(); });
afterEach(() => sandbox.restore());

describe('util.js', () => {
  describe('sanitizeUrl()', () => {
    it('Returns http for localhost', () => {
      const authressApiUrl = 'http://localhost:8080';
      const result = sanitizeUrl(authressApiUrl);
      expect(result).to.eql('http://localhost:8080');
    });

    it('Returns http for localstack', () => {
      const authressApiUrl = 'http://authress.localstack.cloud:4556';
      const result = sanitizeUrl(authressApiUrl);
      expect(result).to.eql('http://authress.localstack.cloud:4556');
    });
    
    it('custom domain returns custom domain', () => {
      const authressApiUrl = 'https://authress.company.com';
      const result = sanitizeUrl(authressApiUrl);
      expect(result).to.eql('https://authress.company.com');
    });

    it('raw authentication domain returns domain', () => {
      const authressApiUrl = 'https://account.login.authress.io';
      const result = sanitizeUrl(authressApiUrl);
      expect(result).to.eql('https://account.login.authress.io');
    });

    it('Convert raw authorization region domain to global authentication. This can be necessary when an account incorrectly uses the authorization domain when really they need to use the authentication one.', () => {
      const authressApiUrl = 'https://account.api-na-east.authress.io';
      const result = sanitizeUrl(authressApiUrl);
      expect(result).to.eql('https://account.login.authress.io');
    });
  });
});

