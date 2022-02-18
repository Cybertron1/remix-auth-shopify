import { AppLoadContext } from "@remix-run/server-runtime";
export interface OAuth2Profile {
    provider: string;
    id?: string;
    displayName?: string;
    name?: {
        familyName?: string;
        givenName?: string;
        middleName?: string;
    };
    emails?: Array<{
        value: string;
        type?: string;
    }>;
    photos?: Array<{
        value: string;
    }>;
}
export interface OAuth2StrategyOptions {
    authorizationURL: string;
    tokenURL: string;
    clientID: string;
    clientSecret: string;
    callbackURL: string;
}
export interface OAuth2StrategyVerifyParams<Profile extends OAuth2Profile, ExtraParams extends Record<string, unknown> = Record<string, never>> {
    accessToken: string;
    refreshToken: string;
    extraParams: ExtraParams;
    profile: Profile;
    context?: AppLoadContext;
}
