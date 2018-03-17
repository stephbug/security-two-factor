<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Request;

use Illuminate\Http\Request as IlluminateRequest;
use StephBug\SecurityModel\Application\Http\Request\AuthenticationRequest;
use StephBug\SecurityModel\Application\Values\EmptyCredentials;
use StephBug\SecurityTwoFactor\Application\Values\TwoFACredentials;
use Symfony\Component\HttpFoundation\Request;

class TwoFAHttpRequest implements AuthenticationRequest
{
    /**
     * @var string
     */
    private $routeName;

    public function __construct(string $routeName)
    {
        $this->routeName = $routeName;
    }

    public function extract(IlluminateRequest $request)
    {
        if($this->matches($request)){
            return TwoFACredentials::fromString($request->input('two_factor_code'));
        }

        return new EmptyCredentials();
    }

    public function matches(Request $request)
    {
        return $this->routeName === $request->route()->getName();
    }
}