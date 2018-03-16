<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Values;

use StephBug\SecurityModel\Application\Values\Contract\SecurityValue;

class TwoFactorCredentialsWithConfirmation extends TwoFACredentials
{
    /**
     * @var string
     */
    private $secret;

    protected function __construct(string $credentials, string $secret)
    {
        parent::__construct($credentials);

        $this->secret = $secret;
    }

    public static function withSecret($credentials, $secret): self
    {
        parent::validateCredentials($credentials);

        parent::validateCredentials($secret);

        return new self($credentials, $secret);
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    public function sameValueAs(SecurityValue $aValue): bool
    {
        return $aValue instanceof $this
            && $this->credentials === $aValue->credentials()
            && $this->secret === $aValue->getSecret();
    }
}