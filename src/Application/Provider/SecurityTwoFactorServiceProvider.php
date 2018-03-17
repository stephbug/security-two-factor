<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Provider;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use StephBug\SecurityTwoFactor\TwoFactor\TwoFactorContext;

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

        $this->app->bind(TwoFactorContext::class, function (Application $app) {
            return new TwoFactorContext(
                $app->make('config')->get('security_two_factor.context', [])
            );
        });
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