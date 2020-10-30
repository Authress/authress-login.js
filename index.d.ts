/* eslint-disable @typescript-eslint/no-empty-interface */
export interface Settings {
  baseUrl: string;
}

declare class Login {
  constructor(settings: Settings): Login;
}

declare class ServiceClientTokenProvider {}

export = { Login };
