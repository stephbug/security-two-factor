<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Firewall;

use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Exception\AuthenticationException;
use StephBug\SecurityModel\Application\Values\SecurityKey;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use StephBug\SecurityModel\Guard\Guard;
use StephBug\SecurityTwoFactor\Application\Event\TwoFactorUserLoginFailed;
use StephBug\SecurityTwoFactor\Application\Event\TwoFAUserLogin;
use StephBug\SecurityTwoFactor\Application\Http\Request\TwoFAAuthenticationRequest;
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
     * @var TwoFAAuthenticationRequest
     */
    private $authenticationRequest;

    /**
     * @var TwoFAResponse
     */
    private $response;

    public function __construct(Guard $guard,
                                TwoFAHandler $twoFAHandler,
                                SecurityKey $securityKey,
                                TwoFAAuthenticationRequest $authenticationRequest,
                                TwoFAResponse $response)
    {
        $this->guard = $guard;
        $this->twoFAHandler = $twoFAHandler;
        $this->securityKey = $securityKey;
        $this->authenticationRequest = $authenticationRequest;
        $this->response = $response;
    }

    public function handle(Request $request, \Closure $next)
    {
        $token = $this->guard->storage()->getToken();

        if ($this->shouldSkip($token)) {
            if ($this->authenticationRequest->matchAtLeastOne($request)) {
                return $this->response->toSafe($request);
            }

            return $next($request);
        }

        $twoFaToken = $this->twoFAHandler->createTwoFactorToken($token, $request, $this->securityKey);

        if ($twoFaToken->isAuthenticated()) {
            if ($this->authenticationRequest->matchAtLeastOne($request)) {
                return $this->response->toSafe($request);
            }

            return $next($request);
        }

        if (!$twoFaToken->isAuthenticated() && !$this->authenticationRequest->matchAtLeastOne($request)) {
            return $this->response->toLogin($request);
        }

        if ($this->authenticationRequest->isFormRequest($request)) {
            return $next($request);
        }

        return $this->processAuthentication($twoFaToken, $request);
    }

    protected function processAuthentication(TwoFactorToken $token, Request $request): Response
    {
        try {
            $authenticatedToken = $this->guard->authenticate($token);

            $this->guard->event()->dispatchEvent(
                new TwoFAUserLogin($authenticatedToken, $request)
            );

            $this->guard->put($authenticatedToken);

            return $this->response->onSuccess($request, $authenticatedToken);
        } catch (AuthenticationException $exception) {
            $this->guard->event()->dispatchEvent(
                new TwoFactorUserLoginFailed(
                    $token, $request, $exception
                )
            );

            return $this->response->toLogin($request, $exception);
        }
    }

    private function shouldSkip(Tokenable $token = null): bool
    {
        return !$token
            || !$this->twoFAHandler->supportsToken($token, $this->securityKey)
            || !$this->twoFAHandler->isTokenStateValid($token);
    }
}