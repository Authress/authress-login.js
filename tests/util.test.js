import { describe, it, afterEach, expect, vi } from 'vitest';
import { sanitizeUrl } from '../src/util.js';

afterEach(() => {
  vi.restoreAllMocks();
});
describe('util.js', () => {
  describe('sanitizeUrl()', () => {
    it('Returns http for localhost', () => {
      const authressApiUrl = 'http://localhost:8080';
      const result = sanitizeUrl(authressApiUrl);
      expect(result).toEqual('http://localhost:8080');
    });

    it('Returns http for localstack', () => {
      const authressApiUrl = 'http://authress.localstack.cloud:4556';
      const result = sanitizeUrl(authressApiUrl);
      expect(result).toEqual('http://authress.localstack.cloud:4556');
    });
    
    it('custom domain returns custom domain', () => {
      const authressApiUrl = 'https://authress.company.com';
      const result = sanitizeUrl(authressApiUrl);
      expect(result).toEqual('https://authress.company.com');
    });

    it('raw authentication domain returns domain', () => {
      const authressApiUrl = 'https://account.login.authress.io';
      const result = sanitizeUrl(authressApiUrl);
      expect(result).toEqual('https://account.login.authress.io');
    });

    it('Convert raw authorization region domain to global authentication. This can be necessary when an account incorrectly uses the authorization domain when really they need to use the authentication one.', () => {
      const authressApiUrl = 'https://account.api-na-east.authress.io';
      const result = sanitizeUrl(authressApiUrl);
      expect(result).toEqual('https://account.login.authress.io');
    });
  });
});
