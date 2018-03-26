<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Authentication\Token;

use StephBug\SecurityModel\Application\Values\Contract\Credentials;
use StephBug\SecurityModel\Application\Values\Security\SecurityKey;
use StephBug\SecurityModel\Guard\Authentication\Token\Token;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;

class TwoFAToken extends Token implements TwoFactorToken
{
    use HasTwoFA;

    /**
     * @var Tokenable
     */
    private $token;

    /**
     * @var Credentials
     */
    private $credentials;

    /**
     * @var SecurityKey
     */
    private $securityKey;

    public function __construct(Tokenable $token, Credentials $credentials, SecurityKey $securityKey)
    {
        parent::__construct($roles = $token->getRoles());

        $this->setUser($token->getUser());
        $this->token = $token;
        $this->credentials = $credentials;
        $this->securityKey = $securityKey;
    }

    public function isAuthenticated(): bool
    {
        if (!$this->isInitialized()) {
            return false;
        }

        return $this->getTwoFAValue()->isAuthenticated() && $this->getSource()->isAuthenticated();
    }

    public function getCredentials(): Credentials
    {
        return $this->credentials;
    }

    public function getSecurityKey(): SecurityKey
    {
        return $this->securityKey;
    }

    public function getSource(): Tokenable
    {
        return $this->token;
    }
}