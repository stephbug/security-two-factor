<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Values;

use StephBug\SecurityModel\Application\Exception\Assert\Secure;
use StephBug\SecurityModel\Application\Values\Contract\Credentials;
use StephBug\SecurityModel\Application\Values\Contract\SecurityValue;

class TwoFACredentials implements Credentials
{
    /**
     * @var string
     */
    protected $credentials;

    protected function __construct(string $credentials)
    {
        $this->credentials = $credentials;
    }

    public static function fromString($credentials): TwoFACredentials
    {
        self::validateCredentials($credentials);

        return new self($credentials);
    }

    protected static function validateCredentials($credentials): void
    {
        $message = 'Two factor code invalid';

        Secure::string($credentials, $message);
        Secure::notEmpty($credentials, $message);
    }

    public function credentials(): string
    {
        return $this->credentials;
    }

    public function sameValueAs(SecurityValue $aValue): bool
    {
        return $aValue instanceof $this && $this->credentials === $aValue->credentials();
    }
}