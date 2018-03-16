<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Authentication\Token;

use StephBug\SecurityModel\Application\Exception\InvalidArgument;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;

trait HasTwoFA
{
    public function initialize(): void
    {
        if ($this->isInitialized()) {
            throw InvalidArgument::reason('2FA is already initialized on token ');
        }

        $this->getSource()->setAttribute(
            $this->getTwoFactorAttribute(),
            new TwoFAValue()
        );
    }

    public function isInitialized(): bool
    {
        return null !== $this->getTwoFAValue();
    }

    public function getTwoFAValue(): ?TwoFAValue
    {
        return $this->getSource()->getAttribute($this->getTwoFactorAttribute());
    }

    public function getTwoFactorAttribute(): string
    {
        return static::TWO_FACTOR_ATTRIBUTE;
    }

    abstract public function getSource(): Tokenable;
}