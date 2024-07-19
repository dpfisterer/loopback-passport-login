import {
  AuthenticateActionProvider as BaseAuthenticateActionProvider,
  AuthenticateFn,
  AuthenticationBindings,
  AuthenticationStrategy,
  AuthenticationOptions,
  USER_PROFILE_NOT_FOUND,
} from '@loopback/authentication';
import {
  Application,
  config,
  CoreBindings,
  Getter,
  inject,
  Provider,
  Setter,
} from '@loopback/core';
import {RedirectRoute, Request} from '@loopback/rest';
import {SecurityBindings, UserProfile} from '@loopback/security';

export class AuthenticateActionProvider
  extends BaseAuthenticateActionProvider
  implements Provider<AuthenticateFn>
{
  constructor(
    @inject(CoreBindings.APPLICATION_INSTANCE) private app: Application,

    @inject.getter(AuthenticationBindings.STRATEGY)
    override getStrategies: Getter<
      AuthenticationStrategy | AuthenticationStrategy[] | undefined
    >,
    @inject.setter(SecurityBindings.USER)
    readonly setCurrentUser: Setter<UserProfile>,
    @inject.setter(AuthenticationBindings.AUTHENTICATION_REDIRECT_URL)
    readonly setRedirectUrl: Setter<string>,
    @inject.setter(AuthenticationBindings.AUTHENTICATION_REDIRECT_STATUS)
    readonly setRedirectStatus: Setter<number>,
  ) {
    super(getStrategies, setCurrentUser, setRedirectUrl, setRedirectStatus);
  }

  override value(): AuthenticateFn {
    return (request: Request) => this.action(request);
  }

  async getCustomStrategies() {
    const GoogleOauth2Authentication =
      await this.app.get<AuthenticationStrategy>(
        'authentication.strategies.GoogleOauth2Authentication',
      );

    return [GoogleOauth2Authentication];
  }

  override async action(request: Request): Promise<UserProfile | undefined> {
    let strategies = await this.getCustomStrategies();
    if (strategies == null) {
      // The invoked operation does not require authentication.
      return undefined;
    }
    // convert to array if required
    strategies = Array.isArray(strategies) ? strategies : [strategies];

    const authErrors: unknown[] = [];
    for (const strategy of strategies) {
      let authResponse: UserProfile | RedirectRoute | undefined = undefined;
      try {
        authResponse = await strategy.authenticate(request);
      } catch (err) {
        // if (this.options.failOnError) {
        //   throw err;
        // }
        authErrors.push(err);
      }

      // response from `strategy.authenticate()` could return an object of
      // type UserProfile or RedirectRoute
      if (RedirectRoute.isRedirectRoute(authResponse)) {
        const redirectOptions = authResponse;
        // bind redirection url and status to the context
        // controller should handle actual redirection
        this.setRedirectUrl(redirectOptions.targetLocation);
        this.setRedirectStatus(redirectOptions.statusCode);
        return;
      } else if (authResponse != null) {
        // if `strategy.authenticate()` returns an object of type UserProfile,
        // set it as current user
        const userProfile = authResponse as UserProfile;
        this.setCurrentUser(userProfile);
        return userProfile;
      }
    }

    if (authErrors.length) {
      throw authErrors[0];
    }
    // important to throw a non-protocol-specific error here
    const error = new Error(
      `User profile not returned from strategy's authenticate function`,
    );
    Object.assign(error, {
      code: USER_PROFILE_NOT_FOUND,
    });
    throw error;
  }
}
