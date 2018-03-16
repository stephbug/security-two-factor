<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\TwoFactor\Factory;

use Illuminate\Contracts\Foundation\Application;
use StephBug\Firewall\Factory\Contracts\AuthenticationServiceFactory;
use StephBug\Firewall\Factory\Payload\PayloadService;
use StephBug\SecurityModel\Application\Values\SecurityKey;
use StephBug\SecurityModel\Guard\Authentication\Token\IdentifierPasswordToken;
use StephBug\SecurityModel\Guard\Authentication\Token\RecallerToken;
use StephBug\SecurityTwoFactor\Application\Http\Request\TwoFAAuthenticationRequest;
use StephBug\SecurityTwoFactor\Application\Http\Request\TwoFAFormRequest;
use StephBug\SecurityTwoFactor\Application\Http\Request\TwoFAHttpRequest;
use StephBug\SecurityTwoFactor\Application\Http\Response\TwoFAEntrypoint;
use StephBug\SecurityTwoFactor\TwoFactor\TwoFAHandler;

abstract class TwoFAAuthenticationFactory implements AuthenticationServiceFactory
{
    /**
     * @var Application
     */
    protected $app;

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    protected function registerHandler(PayloadService $payload): string
    {
        $id = 'firewall.two_factor_firewall.' . $payload->securityKey->value();

        $this->app->bindIf($id, function () use ($payload) {
            return new TwoFAHandler(
                $this->authenticationRequest(),
                $this->supportedToken()
           );
        });

        return $id;
    }

    protected function registerEntrypoint(PayloadService $payload): string
    {
        $entrypointId = 'firewall.two_factor_entrypoint.' . $payload->securityKey->value();

        $this->app->bindIf($entrypointId, TwoFAEntrypoint::class);

        return $entrypointId;
    }

    protected function authenticationRequest(): TwoFAAuthenticationRequest
    {
        return new TwoFAAuthenticationRequest($this->formMatcher(), $this->httpMatcher());
    }

    protected function httpMatcher(): TwoFAHttpRequest
    {
        return new TwoFAHttpRequest();
    }

    protected function formMatcher(): TwoFAFormRequest
    {
        return new TwoFAFormRequest();
    }

    protected function firewallId(SecurityKey $securityKey): string
    {
        return 'firewall.two_factor_firewall.' . $this->serviceKey() . '.' . $securityKey->value();
    }

    protected function supportedToken(): array
    {
        return [
            IdentifierPasswordToken::class,
            RecallerToken::class
        ];
    }

    public function userProviderKey(): ?string
    {
        return null;
    }
}