<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Event;

use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Exception\AuthenticationException;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;

class TwoFactorUserLoginFailed
{
    /**
     * @var Tokenable
     */
    private $token;

    /**
     * @var Request
     */
    private $request;

    /**
     * @var AuthenticationException
     */
    private $exception;

    public function __construct(Tokenable $token, Request $request, AuthenticationException $exception = null)
    {
        $this->token = $token;
        $this->request = $request;
        $this->exception = $exception;
    }

    public function token(): Tokenable
    {
        return $this->token;
    }

    public function request(): Request
    {
        return $this->request;
    }

    public function exception(): ?AuthenticationException
    {
        return $this->exception;
    }
}