declare var studioOauth: StudioOauthApi;

interface StudioOauthApi {
  login(client: string | null, resources: string[]): Promise<StudioOauthToken | null>;
  header(resource: string): Promise<string>;
}

interface StudioOauthToken {
  readonly token: string;
  readonly user: string;
  readonly resources: readonly string[];
  readonly expires: number;
}