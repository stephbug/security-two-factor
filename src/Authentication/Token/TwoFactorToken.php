<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Authentication\Token;

use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;

interface TwoFactorToken
{
    const TWO_FACTOR_ATTRIBUTE = 'two_factor_token_attribute';

    public function initialize(): void;

    public function isInitialized(): bool;

    public function isSourceAuthenticated(): bool;

    public function getTwoFAValue(): ?TwoFAValue;

    public function getTwoFactorAttribute(): string;

    public function getSource(): Tokenable;
}