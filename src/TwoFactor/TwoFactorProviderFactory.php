<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\TwoFactor;

use Illuminate\Contracts\Foundation\Application;
use StephBug\SecurityModel\Application\Exception\InvalidArgument;
use StephBug\SecurityTwoFactor\TwoFactor\Providers\TwoFAProvider;
use StephBug\SecurityTwoFactor\User\UserTwoFactor;

class TwoFactorProviderFactory
{
    /**
     * @var Application
     */
    private $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    public function make(string $provider): TwoFAProvider
    {
        return $this->createProvider($provider);
    }

    public function makeFromUser(UserTwoFactor $user): TwoFAProvider
    {
        return $this->make($user->getTwoFactorProvider());
    }

    protected function createProvider(string $provider): TwoFAProvider
    {
        $config = $this->fromConfig('providers.' . $provider);

        if (!$config) {
            throw InvalidArgument::reason(sprintf('No 2fa config set for provider %s', $provider));
        }

        return $this->app->make($config['service']);
    }

    protected function fromConfig(string $key, $default = null)
    {
        return $this->app->make('config')->get('security_two_factor.' . $key, $default);
    }
}