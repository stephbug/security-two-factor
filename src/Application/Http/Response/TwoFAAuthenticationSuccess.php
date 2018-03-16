<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Response;

use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Http\Response\AuthenticationSuccess;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use Symfony\Component\HttpFoundation\Response;

class TwoFAAuthenticationSuccess implements AuthenticationSuccess
{
    /**
     * @var ResponseFactory
     */
    private $response;

    /**
     * @var string
     */
    private $routeName;

    public function __construct(ResponseFactory $response, string $routeName = 'home')
    {
        $this->response = $response;
        $this->routeName = $routeName;
    }

    public function onAuthenticationSuccess(Request $request, Tokenable $token): Response
    {
        return $this->response->redirectToRoute($this->routeName)
            ->with('message', 'Two factor authentication succeeded');
    }
}