<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Response;

use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Exception\AuthenticationException;
use StephBug\SecurityModel\Application\Exception\AuthorizationException;
use StephBug\SecurityModel\Application\Http\Entrypoint\Entrypoint;
use StephBug\SecurityModel\Application\Http\Response\AuthenticationSuccess;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use Symfony\Component\HttpFoundation\Response;

class TwoFAResponse
{
    /**
     * @var Entrypoint
     */
    private $entrypoint;

    /**
     * @var AuthenticationSuccess
     */
    private $authenticationSuccess;

    /**
     * @var TwoFASafeResponse
     */
    private $safeResponse;

    public function __construct(Entrypoint $entrypoint,
                                AuthenticationSuccess $authenticationSuccess,
                                TwoFASafeResponse $safeResponse)
    {
        $this->entrypoint = $entrypoint;
        $this->authenticationSuccess = $authenticationSuccess;
        $this->safeResponse = $safeResponse;
    }

    public function toLogin(Request $request, AuthenticationException $exception = null): Response
    {
        return $this->entrypoint->startAuthentication($request, $exception);
    }

    public function onSuccess(Request $request, Tokenable $token): Response
    {
        return $this->authenticationSuccess->onAuthenticationSuccess($request, $token);
    }

    public function toSafe(Request $request, Tokenable $token = null, AuthorizationException $exception = null): Response
    {
        return $this->safeResponse->toSafe($request, $token, $exception);
    }
}