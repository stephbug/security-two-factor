<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Authentication\Token;

use StephBug\SecurityModel\Application\Exception\InvalidArgument;
use StephBug\SecurityModel\Application\Values\Contract\Credentials;
use StephBug\SecurityModel\Application\Values\SecurityKey;
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
        parent::__construct($roles = $token->getUser()->getRoles());

        $this->setUser($token->getUser());
        $this->token = $token;
        $this->credentials = $credentials;
        $this->securityKey = $securityKey;

        count($roles) > 0 and $this->setAuthenticated(true);
    }

    public function isAuthenticated(): bool
    {
        return parent::isAuthenticated() && $this->isSourceAuthenticated();
    }

    public function setAuthenticated(bool $authenticated): void
    {
        throw InvalidArgument::reason(
            'Can not set authenticated token after instantiation'
        );
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