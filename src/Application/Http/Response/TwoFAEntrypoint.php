<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Response;

use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Exception\AuthenticationException;
use StephBug\SecurityModel\Application\Http\Entrypoint\Entrypoint;
use Symfony\Component\HttpFoundation\Response;

class TwoFAEntrypoint implements Entrypoint
{

    public function startAuthentication(Request $request, AuthenticationException $exception = null): Response
    {
        // TODO: Implement startAuthentication() method.
    }
}