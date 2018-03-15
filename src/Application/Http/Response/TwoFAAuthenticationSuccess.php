<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Response;

use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Http\Response\AuthenticationSuccess;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use Symfony\Component\HttpFoundation\Response;

class TwoFAAuthenticationSuccess implements AuthenticationSuccess
{

    public function onAuthenticationSuccess(Request $request, Tokenable $token): Response
    {
        // TODO: Implement onAuthenticationSuccess() method.
    }
}