<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\TwoFactor\Providers;

use Illuminate\Contracts\View\Factory;
use Illuminate\View\View;
use PragmaRX\Google2FA\Google2FA;
use StephBug\SecurityModel\Application\Values\Contract\Credentials;
use StephBug\SecurityTwoFactor\Application\Values\TwoFactorCredentialsWithConfirmation;

class Google2FAProvider implements TwoFAProvider
{
    /**
     * @var Google2FA
     */
    private $provider;

    /**
     * @var Factory
     */
    private $view;

    public function __construct(Google2FA $provider, Factory $view)
    {
        $this->provider = $provider;
        $this->view = $view;
    }

    public function produceUserKey(): string
    {
        return $this->provider->generateSecretKey();
    }

    public function produceUserUrl(string $identifier, string $userSecret): string
    {
        $this->provider->setAllowInsecureCallToGoogleApis(true);

        return $this->provider->getQRCodeGoogleUrl(
            'my_company',
            $identifier,
            $userSecret
        );
    }

    public function produceUserView(string $identifier, string $userSecret): void
    {
        $this->view->composer('front.auth.two_factor_login', function (View $view) use ($identifier, $userSecret) {
            $view->with('scanCodeTest', $this->produceUserUrl($identifier, $userSecret));
        });
    }

    public function isCredentialsValid(Credentials $credentials): bool
    {
        if ($credentials instanceof TwoFactorCredentialsWithConfirmation) {
            return $this->provider->verifyKey($credentials->getSecret(), $credentials->credentials());
        }

        return false;
    }
}