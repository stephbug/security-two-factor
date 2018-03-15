<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Request;

use Illuminate\Http\Request as IlluminateRequest;
use StephBug\SecurityModel\Application\Http\Request\AuthenticationRequest;
use Symfony\Component\HttpFoundation\Request;

class TwoFAFormRequest implements AuthenticationRequest
{
    public function extract(IlluminateRequest $request)
    {
        // TODO: Implement extract() method.
    }

    public function matches(Request $request)
    {
        // TODO: Implement matches() method.
    }
}