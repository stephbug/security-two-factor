<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Request;

use Illuminate\Http\Request as IlluminateRequest;
use StephBug\SecurityModel\Application\Http\Request\AuthenticationRequest;
use StephBug\SecurityModel\Application\Values\Contract\Credentials;
use StephBug\SecurityModel\Application\Values\EmptyCredentials;
use Symfony\Component\HttpFoundation\Request;

class TwoFAAuthenticationRequest implements AuthenticationRequest
{
    /**
     * @var TwoFAFormRequest
     */
    private $formRequest;

    /**
     * @var TwoFAHttpRequest
     */
    private $httpRequest;

    public function __construct(TwoFAFormRequest $formRequest, TwoFAHttpRequest $httpRequest)
    {
        $this->formRequest = $formRequest;
        $this->httpRequest = $httpRequest;
    }

    public function extract(IlluminateRequest $request): Credentials
    {
        if ($this->isFormRequest($request)) {
            return $this->formRequest->extract($request);
        }

        if ($this->isHttpRequest($request)) {
            return $this->httpRequest->extract($request);
        }

        return new EmptyCredentials();
    }

    public function matches(Request $request)
    {
        if ($this->isFormRequest($request)) {
            return $this->formRequest->matches($request);
        }

        return $this->httpRequest->matches($request);
    }

    public function matchAtLeastOne(IlluminateRequest $request): bool
    {
        if ($this->isFormRequest($request) || $this->isHttpRequest($request)) {
            return true;
        }

        return false;
    }

    public function isFormRequest(IlluminateRequest $request): bool
    {
        return $this->formRequest->matches($request);
    }

    public function isHttpRequest(IlluminateRequest $request): bool
    {
        return $this->httpRequest->matches($request);
    }

    public function form(): TwoFAFormRequest
    {
        return $this->formRequest;
    }

    public function http(): TwoFAHttpRequest
    {
        return $this->httpRequest;
    }
}