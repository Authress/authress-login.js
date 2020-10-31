/* eslint-disable @typescript-eslint/no-empty-interface */
export interface Settings {
  baseUrl: string;
}

declare class LoginClient {
  constructor(settings: Settings): LoginClient;
}

declare class ServiceClientTokenProvider {}

export = { LoginClient: Login };
