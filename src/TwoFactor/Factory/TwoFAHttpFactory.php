<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\TwoFactor\Factory;

use Illuminate\Contracts\Foundation\Application;
use StephBug\Firewall\Factory\Payload\PayloadFactory;
use StephBug\Firewall\Factory\Payload\PayloadService;
use StephBug\SecurityModel\Guard\Guard;
use StephBug\SecurityTwoFactor\Application\Http\Firewall\TwoFAAuthenticationFirewall;
use StephBug\SecurityTwoFactor\Application\Http\Response\TwoFAAuthenticationSuccess;
use StephBug\SecurityTwoFactor\Application\Http\Response\TwoFAResponse;
use StephBug\SecurityTwoFactor\Authentication\Provider\TwoFAAuthenticationProvider;
use StephBug\SecurityTwoFactor\TwoFactor\TwoFactorProviderFactory;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;

class TwoFAHttpFactory extends TwoFAAuthenticationFactory
{
    public function create(PayloadService $payload): PayloadFactory
    {
        $entrypointId = $this->registerEntrypoint($payload);

        return (new PayloadFactory())
            ->setFirewall($this->registerFirewall($payload, $entrypointId))
            ->setProvider($this->registerProvider($payload))
            ->setEntrypoint($entrypointId);
    }

    protected function registerFirewall(PayloadService $payload, string $entrypointId): string
    {
        $id = 'firewall.two_factor_firewall.' . $this->serviceKey() . '.' . $payload->securityKey->value();

        $this->app->bind($id, function (Application $app) use ($payload, $entrypointId) {
            return new TwoFAAuthenticationFirewall(
                $app->make(Guard::class),
                $app->make($this->registerHandler($payload)),
                $payload->securityKey,
                $this->authenticationRequest(),
                $this->getTwoFactorResponse($payload)
            );
        });

        return $id;
    }

    protected function registerProvider(PayloadService $payload): string
    {
        $id = 'firewall.two_factor_provider.' . $this->serviceKey() . '.' . $payload->securityKey->value();

        $this->app->bind($id, function (Application $app) use ($payload) {
            return new TwoFAAuthenticationProvider(
                $app->make(TwoFactorProviderFactory::class),
                $payload->securityKey
            );
        });

        return $id;
    }

    protected function getTwoFactorResponse(PayloadService $payload): TwoFAResponse
    {
        return new TwoFAResponse(
            $this->app->make($this->registerEntrypoint($payload)),
            $this->app->make(TwoFAAuthenticationSuccess::class)
        );
    }

    public function position(): string
    {
        return 'http';
    }

    public function matcher(): ?RequestMatcherInterface
    {
        return $this->httpMatcher();
    }

    public function serviceKey(): string
    {
        return 'two-factor-http';
    }
}