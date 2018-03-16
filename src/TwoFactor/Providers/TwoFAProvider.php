<?php

namespace StephBug\SecurityTwoFactor\TwoFactor\Providers;

use StephBug\SecurityModel\Application\Values\Contract\Credentials;

interface TwoFAProvider
{
    public function isCredentialsValid(Credentials $credentials): bool;
}