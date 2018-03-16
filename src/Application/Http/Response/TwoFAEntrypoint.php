<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Response;

use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Exception\AuthenticationException;
use StephBug\SecurityModel\Application\Http\Entrypoint\Entrypoint;
use Symfony\Component\HttpFoundation\Response;

class TwoFAEntrypoint implements Entrypoint
{
    /**
     * @var ResponseFactory
     */
    private $response;

    /**
     * @var string
     */
    private $routeName;

    public function __construct(ResponseFactory $response, string $routeName = 'front.auth.two_factor_login')
    {
        $this->response = $response;
        $this->routeName = $routeName;
    }

    public function startAuthentication(Request $request, AuthenticationException $exception = null): Response
    {
        // todo route name must be the login two factor route
        return $this->response->redirectToRoute($this->routeName)
            ->with('message', $exception ? $exception->getMessage() : 'Two factor authentication failure');
    }
}