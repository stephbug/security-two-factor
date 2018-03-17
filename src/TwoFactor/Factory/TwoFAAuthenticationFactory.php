<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\TwoFactor\Factory;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Routing\ResponseFactory;
use StephBug\Firewall\Factory\Contracts\AuthenticationServiceFactory;
use StephBug\Firewall\Factory\Payload\PayloadService;
use StephBug\SecurityModel\Application\Values\SecurityKey;
use StephBug\SecurityTwoFactor\Application\Http\Request\TwoFAAuthenticationRequest;
use StephBug\SecurityTwoFactor\Application\Http\Request\TwoFAFormRequest;
use StephBug\SecurityTwoFactor\Application\Http\Request\TwoFAHttpRequest;
use StephBug\SecurityTwoFactor\Application\Http\Response\TwoFAEntrypoint;
use StephBug\SecurityTwoFactor\TwoFactor\TwoFactorContext;
use StephBug\SecurityTwoFactor\TwoFactor\TwoFAHandler;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;

abstract class TwoFAAuthenticationFactory implements AuthenticationServiceFactory
{
    /**
     * @var Application
     */
    protected $app;

    /**
     * @var TwoFactorContext
     */
    protected $twoFactorContext;

    public function __construct(Application $app, TwoFactorContext $twoFactorContext)
    {
        $this->app = $app;
        $this->twoFactorContext = $twoFactorContext;
    }

    protected function registerHandler(PayloadService $payload): string
    {
        $id = 'firewall.two_factor_firewall.' . $payload->securityKey->value();

        $this->app->bindIf($id, function () use ($payload) {
            return new TwoFAHandler(
                $this->authenticationRequest($payload->securityKey),
                $this->twoFactorContext->supportedToken($payload->securityKey->value())
            );
        });

        return $id;
    }

    protected function registerEntrypoint(PayloadService $payload): string
    {
        $entrypointId = 'firewall.two_factor_entrypoint.' . $payload->securityKey->value();

        $this->app->bindIf($entrypointId, function (Application $app) use ($payload) {
            return new TwoFAEntrypoint(
                $app->make(ResponseFactory::class),
                $this->twoFactorContext->login($payload->securityKey->value())
            );
        });

        return $entrypointId;
    }

    protected function authenticationRequest(SecurityKey $securityKey): TwoFAAuthenticationRequest
    {
        return new TwoFAAuthenticationRequest(
            $this->formMatcher($securityKey),
            $this->httpMatcher($securityKey)
        );
    }

    protected function httpMatcher(SecurityKey $securityKey): TwoFAHttpRequest
    {
        return new TwoFAHttpRequest(
            $this->twoFactorContext->loginPost($securityKey->value())
        );
    }

    protected function formMatcher(SecurityKey $securityKey): TwoFAFormRequest
    {
        return new TwoFAFormRequest(
            $this->twoFactorContext->login($securityKey->value())
        );
    }

    protected function firewallId(SecurityKey $securityKey): string
    {
        return 'firewall.two_factor_firewall.' . $this->serviceKey() . '.' . $securityKey->value();
    }

    public function userProviderKey(): ?string
    {
        return null;
    }

    public function matcher(): ?RequestMatcherInterface
    {
        return null;
    }
}