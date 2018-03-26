<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Request;

use Illuminate\Http\Request as IlluminateRequest;
use StephBug\SecurityModel\Application\Http\Request\AuthenticationRequest;

interface TwoFAMatcher extends AuthenticationRequest
{
    public function matchAtLeastOne(IlluminateRequest $request): bool;

    public function isFormRequest(IlluminateRequest $request): bool;

    public function isHttpRequest(IlluminateRequest $request): bool;
}