import { SessionStorage } from "@remix-run/server-runtime";
import { AuthenticateOptions, Strategy, StrategyVerifyCallback } from "remix-auth";
import { OAuth2Profile, OAuth2StrategyOptions, OAuth2StrategyVerifyParams } from "./types";
/**
 * The OAuth 2.0 authentication strategy authenticates requests using the OAuth
 * 2.0 framework.
 *
 * OAuth 2.0 provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Facebook.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * returning the resulting user object.
 *
 * An AuthorizationError should be raised to indicate an authentication failure.
 *
 * Options:
 * - `authorizationURL`  URL used to obtain an authorization grant
 * - `tokenURL`          URL used to obtain an access token
 * - `clientID`          identifies client to service provider
 * - `clientSecret`      secret used to establish ownership of the client identifier
 * - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *
 * @example
 * authenticator.use(new OAuth2Strategy(
 *   {
 *     authorizationURL: 'https://www.example.com/oauth2/authorize',
 *     tokenURL: 'https://www.example.com/oauth2/token',
 *     clientID: '123-456-789',
 *     clientSecret: 'shhh-its-a-secret'
 *     callbackURL: 'https://www.example.net/auth/example/callback'
 *   },
 *   async ({ accessToken, refreshToken, profile }) => {
 *     return await User.findOrCreate(...);
 *   }
 * ));
 */
export declare class OAuth2Strategy<User, Profile extends OAuth2Profile, ExtraParams extends Record<string, unknown> = Record<string, never>> extends Strategy<User, OAuth2StrategyVerifyParams<Profile, ExtraParams>> {
    name: string;
    protected authorizationURL: string;
    protected tokenURL: string;
    protected clientID: string;
    protected clientSecret: string;
    protected callbackURL: string;
    private sessionStateKey;
    constructor(options: OAuth2StrategyOptions, verify: StrategyVerifyCallback<User, OAuth2StrategyVerifyParams<Profile, ExtraParams>>);
    authenticate(request: Request, sessionStorage: SessionStorage, options: AuthenticateOptions): Promise<User>;
    /**
     * Retrieve user profile from service provider.
     *
     * OAuth 2.0-based authentication strategies can override this function in
     * order to load the user's profile from the service provider.  This assists
     * applications (and users of those applications) in the initial registration
     * process by automatically submitting required information.
     */
    protected userProfile(accessToken: string, params: ExtraParams): Promise<Profile>;
    /**
     * Return extra parameters to be included in the authorization request.
     *
     * Some OAuth 2.0 providers allow additional, non-standard parameters to be
     * included when requesting authorization.  Since these parameters are not
     * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
     * strategies can override this function in order to populate these
     * parameters as required by the provider.
     */
    protected authorizationParams(params: URLSearchParams): URLSearchParams;
    /**
     * Return extra parameters to be included in the token request.
     *
     * Some OAuth 2.0 providers allow additional, non-standard parameters to be
     * included when requesting an access token.  Since these parameters are not
     * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
     * strategies can override this function in order to populate these
     * parameters as required by the provider.
     */
    protected tokenParams(): URLSearchParams;
    protected getAccessToken(response: Response): Promise<{
        accessToken: string;
        refreshToken: string;
        extraParams: ExtraParams;
    }>;
    private getCallbackURL;
    private getAuthorizationURL;
    private generateState;
    /**
     * Format the data to be sent in the request body to the token endpoint.
     */
    private fetchAccessToken;
}
