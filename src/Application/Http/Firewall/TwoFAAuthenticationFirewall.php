<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Firewall;

use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Exception\AuthenticationException;
use StephBug\SecurityModel\Application\Values\Security\SecurityKey;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use StephBug\SecurityModel\Guard\Guard;
use StephBug\SecurityTwoFactor\Application\Event\TwoFAUserLogin;
use StephBug\SecurityTwoFactor\Application\Event\TwoFAUserLoginAttempt;
use StephBug\SecurityTwoFactor\Application\Event\TwoFAUserLoginFailed;
use StephBug\SecurityTwoFactor\Application\Http\Request\TwoFAMatcher;
use StephBug\SecurityTwoFactor\Application\Http\Response\TwoFAResponse;
use StephBug\SecurityTwoFactor\Authentication\Token\TwoFactorToken;
use StephBug\SecurityTwoFactor\TwoFactor\TwoFAHandler;
use Symfony\Component\HttpFoundation\Response;

class TwoFAAuthenticationFirewall
{
    /**
     * @var Guard
     */
    private $guard;

    /**
     * @var TwoFAHandler
     */
    private $twoFAHandler;

    /**
     * @var SecurityKey
     */
    private $securityKey;

    /**
     * @var TwoFAMatcher
     */
    private $matcher;

    /**
     * @var TwoFAResponse
     */
    private $response;

    /**
     * @var array
     */
    private $excludedRoutes;

    public function __construct(Guard $guard,
                                TwoFAHandler $twoFAHandler,
                                SecurityKey $securityKey,
                                TwoFAMatcher $matcher,
                                TwoFAResponse $response,
                                array $excludedRoutes = [])
    {
        $this->guard = $guard;
        $this->twoFAHandler = $twoFAHandler;
        $this->securityKey = $securityKey;
        $this->matcher = $matcher;
        $this->response = $response;
        $this->excludedRoutes = $excludedRoutes;
    }

    public function handle(Request $request, \Closure $next)
    {
        if ($this->isExcludedRoute($request)) {
            return $next($request);
        }

        $token = $this->guard->storage()->getToken();

        if ($this->isNotSupportedToken($token)) {
            if ($this->matchTwoFactorRoutes($request)) {
                return $this->response->toSafe($request, $token);
            }

            return $next($request);
        }

        $twoFaToken = $this->twoFAHandler->createTwoFactorToken($token, $request, $this->securityKey);

        if ($twoFaToken->isAuthenticated()) {
            if ($this->matchTwoFactorRoutes($request)) {
                return $this->response->toSafe($request, $token);
            }

            return $next($request);
        }

        if (!$twoFaToken->isAuthenticated() && !$this->matchTwoFactorRoutes($request)) {
            return $this->response->toLogin($request);
        }

        if ($this->matcher->isFormRequest($request)) {
            return $next($request);
        }

        return $this->processAuthentication($twoFaToken, $request);
    }

    protected function processAuthentication(TwoFactorToken $token, Request $request): Response
    {
        try {
            $this->guard->event()->dispatchEvent(
                new TwoFAUserLoginAttempt($token, $request)
            );

            $authenticatedToken = $this->guard->authenticate($token);

            $this->guard->event()->dispatchEvent(
                new TwoFAUserLogin($authenticatedToken, $request)
            );

            $this->guard->put($authenticatedToken);

            return $this->response->onSuccess($request, $authenticatedToken);
        } catch (AuthenticationException $exception) {
            $this->guard->event()->dispatchEvent(
                new TwoFAUserLoginFailed(
                    $token, $request, $exception
                )
            );

            return $this->response->toLogin($request, $exception);
        }
    }

    private function isNotSupportedToken(Tokenable $token = null): bool
    {
        return !$token
            || !$this->twoFAHandler->supportsToken($token, $this->securityKey)
            || !$this->twoFAHandler->isTokenStateValid($token);
    }

    private function matchTwoFactorRoutes(Request $request): bool
    {
        return $this->matcher->matchAtLeastOne($request);
    }

    private function isExcludedRoute(Request $request): bool
    {
        if ($routeName = $request->route()->getName()) {
            return in_array($routeName, $this->excludedRoutes);
        }

        return false;
    }
}