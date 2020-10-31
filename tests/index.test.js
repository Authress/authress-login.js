const { describe, it, beforeEach, afterEach } = require('mocha');
const sinon = require('sinon');
const { expect } = require('chai');

const { LoginClient } = require('../index');

let sandbox;
beforeEach(() => { sandbox = sinon.createSandbox(); });
afterEach(() => sandbox.restore());

describe('index.js', () => {
  describe('LoginClient', () => {
    it('constructor', () => {
      const loginClient = new LoginClient({ authenticationServiceUrl: 'https:/login.test.com' });
      expect(loginClient).to.not.eql(null);
    });
  });
});

