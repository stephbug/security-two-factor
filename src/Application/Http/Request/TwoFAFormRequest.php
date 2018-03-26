<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Request;

use Illuminate\Http\Request as IlluminateRequest;
use StephBug\SecurityModel\Application\Http\Request\AuthenticationRequest;
use StephBug\SecurityModel\Application\Values\Contract\Credentials;
use StephBug\SecurityModel\Application\Values\User\EmptyCredentials;
use Symfony\Component\HttpFoundation\Request;

class TwoFAFormRequest implements AuthenticationRequest
{
    /**
     * @var string
     */
    private $routeName;

    public function __construct(string $routeName)
    {
        $this->routeName = $routeName;
    }

    public function extract(IlluminateRequest $request): Credentials
    {
        return new EmptyCredentials();
    }

    public function matches(Request $request): bool
    {
        return $this->routeName === $request->route()->getName();
    }
}