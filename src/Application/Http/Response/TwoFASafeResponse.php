<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Response;

use Illuminate\Contracts\Routing\ResponseFactory;
use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Exception\AuthorizationException;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use Symfony\Component\HttpFoundation\Response;

class TwoFASafeResponse
{
    /**
     * @var ResponseFactory
     */
    private $response;

    /**
     * @var string
     */
    private $routeName;

    public function __construct(ResponseFactory $response, string $routeName)
    {
        $this->response = $response;
        $this->routeName = $routeName;
    }

    public function toSafe(Request $request, Tokenable $token = null, AuthorizationException $exception = null): Response
    {
        return $this->response->redirectToRoute($this->routeName)
            ->with('message', $exception ? $exception->getMessage() : 'Authorization denied');
    }
}