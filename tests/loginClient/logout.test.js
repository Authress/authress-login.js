const { describe, it, beforeEach, afterEach } = require('mocha');
const sinon = require('sinon');
const { expect } = require('chai');

const { LoginClient } = require('../../src/index');
const windowManager = require('../../src/windowManager');
const userIdentityTokenStorageManager = require('../../src/userIdentityTokenStorageManager.js');
const httpClient = require('../../src/httpClient.js');

let sandbox;
beforeEach(() => { sandbox = sinon.createSandbox(); });
afterEach(() => sandbox.restore());

let requestedRedirectUrl;

requestedRedirectUrl = 'https://valid-redirect.url';

describe('loginClient.js', () => {
  describe('logout', () => {
    it('should clear the user identity token storage and sanitize query parameters', async () => {
      const setTimeoutStub = sandbox.stub(global, 'setTimeout').callsFake(cb => cb());

      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);
      userIdentityTokenStorageManagerMock.expects('clear').once();

      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = sandbox.stub(loginClient, 'sanitizeQueryParameters');
      sanitizeQueryParametersStub.returns();

      await loginClient.logout(requestedRedirectUrl);

      expect(setTimeoutStub.calledOnce).to.eql(true);
      expect(sanitizeQueryParametersStub.calledOnce).to.eql(true);
      userIdentityTokenStorageManagerMock.verify();
    });

    it('should attempt to delete the session if credentials are enabled', async () => {
      const setTimeoutStub = sandbox.stub(global, 'setTimeout').callsFake(cb => cb());

      const deleteMock = sandbox.mock(httpClient.prototype).expects('delete').once().withArgs('/session', true);
      const assignMock = sandbox.mock(windowManager).expects('assign').once().withArgs(requestedRedirectUrl);

      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);
      userIdentityTokenStorageManagerMock.expects('clear').once();

      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = sandbox.stub(loginClient, 'sanitizeQueryParameters');
      sanitizeQueryParametersStub.returns();

      loginClient.enableCredentials = true;
      await loginClient.logout(requestedRedirectUrl);

      expect(setTimeoutStub.calledOnce).to.eql(false);
      expect(sanitizeQueryParametersStub.calledOnce).to.eql(true);
      userIdentityTokenStorageManagerMock.verify();
      deleteMock.verify();
      assignMock.verify();
    });

    it('should attempt to delete the session if credentials are enabled and work for relative urls as well', async () => {
      const setTimeoutStub = sandbox.stub(global, 'setTimeout').callsFake(cb => cb());

      const relativeUrl = '/relative-url';

      const deleteMock = sandbox.mock(httpClient.prototype).expects('delete').once().withArgs('/session', true);
      const assignMock = sandbox.mock(windowManager).expects('assign').once().withArgs(relativeUrl);

      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);
      userIdentityTokenStorageManagerMock.expects('clear').once();

      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = sandbox.stub(loginClient, 'sanitizeQueryParameters');
      sanitizeQueryParametersStub.returns();

      loginClient.enableCredentials = true;
      await loginClient.logout(relativeUrl);

      expect(setTimeoutStub.calledOnce).to.eql(false);
      expect(sanitizeQueryParametersStub.calledOnce).to.eql(true);
      userIdentityTokenStorageManagerMock.verify();
      deleteMock.verify();
      assignMock.verify();
    });

    it('should attempt to delete the session if credentials are enabled and work for no redirect url presented', async () => {
      const setTimeoutStub = sandbox.stub(global, 'setTimeout').callsFake(cb => cb());

      const relativeUrl = null;

      const deleteMock = sandbox.mock(httpClient.prototype).expects('delete').once().withArgs('/session', true);

      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);
      userIdentityTokenStorageManagerMock.expects('clear').once();

      const loginClient = new LoginClient({ authressApiUrl: 'https://unit-test.authress.io', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = sandbox.stub(loginClient, 'sanitizeQueryParameters');
      sanitizeQueryParametersStub.returns();

      loginClient.enableCredentials = true;
      await loginClient.logout(relativeUrl);

      expect(setTimeoutStub.calledOnce).to.eql(false);
      expect(sanitizeQueryParametersStub.calledOnce).to.eql(true);
      userIdentityTokenStorageManagerMock.verify();
      deleteMock.verify();
    });

    it('should assign fullLogoutUrl if session deletion fails', async () => {
      const setTimeoutStub = sandbox.stub(global, 'setTimeout').callsFake(cb => cb());

      const deleteMock = sandbox.mock(httpClient.prototype).expects('delete').rejects(new Error('Failed to delete session'));
      const assignMock = sandbox.mock(windowManager).expects('assign').once();
      const getCurrentLocationMock = sandbox.mock(windowManager).expects('getCurrentLocation').returns({ href: 'https://current.location' });

      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);
      userIdentityTokenStorageManagerMock.expects('clear').once();

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = sandbox.stub(loginClient, 'sanitizeQueryParameters');
      sanitizeQueryParametersStub.returns();

      loginClient.enableCredentials = true;
      await loginClient.logout(requestedRedirectUrl);

      expect(setTimeoutStub.calledOnce).to.eql(true);
      expect(sanitizeQueryParametersStub.calledOnce).to.eql(true);
      userIdentityTokenStorageManagerMock.verify();
      deleteMock.verify();
      assignMock.verify();
      getCurrentLocationMock.verify();
    });

    it('should assign the fullLogoutUrl with redirect_uri and client_id when credentials are not enabled', async () => {
      const setTimeoutStub = sandbox.stub(global, 'setTimeout').callsFake(cb => cb());

      const fullLogoutUrl = 'https://auth.example.com/logout?redirect_uri=https%3A%2F%2Fvalid-redirect.url&client_id=app_id';
      const assignMock = sandbox.mock(windowManager).expects('assign').once().withArgs(fullLogoutUrl);
      const getCurrentLocationMock = sandbox.mock(windowManager).expects('getCurrentLocation').returns({ href: 'https://valid-redirect.url' });

      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);
      userIdentityTokenStorageManagerMock.expects('clear').once();

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = sandbox.stub(loginClient, 'sanitizeQueryParameters');
      sanitizeQueryParametersStub.returns();

      await loginClient.logout(requestedRedirectUrl);

      expect(setTimeoutStub.calledOnce).to.eql(true);
      expect(sanitizeQueryParametersStub.calledOnce).to.eql(true);
      userIdentityTokenStorageManagerMock.verify();
      assignMock.verify();
      getCurrentLocationMock.verify();
    });

    it('should handle relative requestedRedirectUrl and resolve using current location as /', async () => {
      const setTimeoutStub = sandbox.stub(global, 'setTimeout').callsFake(cb => cb());

      const relativeUrl = '/';

      const windowManagerMock = sandbox.mock(windowManager);
      windowManagerMock.expects('assign').once().withArgs('https://auth.example.com/logout?redirect_uri=https%3A%2F%2Fcurrent.location%2F&client_id=app_id');
      windowManagerMock.expects('getCurrentLocation').twice().returns({ href: 'https://current.location' });

      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);
      userIdentityTokenStorageManagerMock.expects('clear').once();

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = sandbox.stub(loginClient, 'sanitizeQueryParameters');
      sanitizeQueryParametersStub.returns();

      await loginClient.logout(relativeUrl);

      expect(setTimeoutStub.calledOnce).to.eql(true);
      expect(sanitizeQueryParametersStub.calledOnce).to.eql(true);
      userIdentityTokenStorageManagerMock.verify();
      windowManagerMock.verify();
    });

    it('should handle relative requestedRedirectUrl and resolve using current location as /relative-url', async () => {
      const setTimeoutStub = sandbox.stub(global, 'setTimeout').callsFake(cb => cb());

      const relativeUrl = '/relative-url';
      const windowManagerMock = sandbox.mock(windowManager);
      windowManagerMock.expects('assign').once().withArgs('https://auth.example.com/logout?redirect_uri=https%3A%2F%2Fcurrent.location%2Frelative-url&client_id=app_id');
      windowManagerMock.expects('getCurrentLocation').twice().returns({ href: 'https://current.location' });

      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);
      userIdentityTokenStorageManagerMock.expects('clear').once();

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = sandbox.stub(loginClient, 'sanitizeQueryParameters');
      sanitizeQueryParametersStub.returns();
      
      await loginClient.logout(relativeUrl);

      expect(setTimeoutStub.calledOnce).to.eql(true);
      expect(sanitizeQueryParametersStub.calledOnce).to.eql(true);
      userIdentityTokenStorageManagerMock.verify();
      windowManagerMock.verify();
    });

    it('should set lastSessionCheck to 0 after logging out', async () => {
      const setTimeoutStub = sandbox.stub(global, 'setTimeout').callsFake(cb => cb());
      const assignMock = sandbox.mock(windowManager).expects('assign').once();

      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);
      userIdentityTokenStorageManagerMock.expects('clear').once();

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = sandbox.stub(loginClient, 'sanitizeQueryParameters');
      sanitizeQueryParametersStub.returns();

      loginClient.lastSessionCheck = 12345;
      await loginClient.logout(requestedRedirectUrl);

      expect(setTimeoutStub.calledOnce).to.eql(true);
      expect(sanitizeQueryParametersStub.calledOnce).to.eql(true);
      userIdentityTokenStorageManagerMock.verify();
      expect(loginClient.lastSessionCheck).to.equal(0);
      assignMock.verify();
    });

    it('should wait for 500ms after logging out', async () => {
      const clock = sandbox.useFakeTimers();
      const assignMock = sandbox.mock(windowManager).expects('assign').once();

      const userIdentityTokenStorageManagerMock = sandbox.mock(userIdentityTokenStorageManager);
      userIdentityTokenStorageManagerMock.expects('clear').once();

      const loginClient = new LoginClient({ authressApiUrl: 'https://auth.example.com', applicationId: 'app_id', skipBackgroundCredentialsCheck: true });
      const sanitizeQueryParametersStub = sandbox.stub(loginClient, 'sanitizeQueryParameters');
      sanitizeQueryParametersStub.returns();

      const logoutAsync = loginClient.logout(requestedRedirectUrl);
      clock.tick(500);
      await logoutAsync;

      expect(sanitizeQueryParametersStub.calledOnce).to.eql(true);
      userIdentityTokenStorageManagerMock.verify();
      assignMock.verify();
      clock.restore();
    });
  });
});
