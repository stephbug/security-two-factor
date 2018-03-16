<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Provider;

use Illuminate\Support\ServiceProvider;

class SecurityTwoFactorServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->publishes(
            [$this->getConfigPath() => config_path('security_two_factor.php')],
            'config'
        );
    }

    public function register(): void
    {
        $this->mergeConfig();
    }

    protected function mergeConfig(): void
    {
        $this->mergeConfigFrom($this->getConfigPath(), 'security_two_factor');
    }

    protected function getConfigPath(): string
    {
        return __DIR__ . '/../../../config/security_two_factor.php';
    }
}