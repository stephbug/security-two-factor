<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\User;

interface UserTwoFactor
{
    public function isTwoFactorEnabled(): bool;

    public function getTwoFactorProvider(): ?string;

    public function getTwoFactorUserSecret(): ?string;
}