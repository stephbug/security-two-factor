<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Event;

use Illuminate\Http\Request;
use StephBug\SecurityTwoFactor\Authentication\Token\TwoFactorToken;

class TwoFAUserInitialized
{
    /**
     * @var TwoFactorToken
     */
    private $token;

    /**
     * @var Request
     */
    private $request;

    public function __construct(TwoFactorToken $token, Request $request)
    {
        $this->token = $token;
        $this->request = $request;
    }

    public function token(): TwoFactorToken
    {
        return $this->token;
    }

    public function request(): Request
    {
        return $this->request;
    }
}