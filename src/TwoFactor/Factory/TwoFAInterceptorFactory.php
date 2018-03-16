<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\TwoFactor\Factory;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use StephBug\Firewall\Factory\Payload\PayloadFactory;
use StephBug\Firewall\Factory\Payload\PayloadService;
use StephBug\SecurityModel\Guard\Guard;
use StephBug\SecurityTwoFactor\Application\Http\Firewall\TwoFAInterceptor;
use Symfony\Component\HttpFoundation\RequestMatcherInterface;

class TwoFAInterceptorFactory extends TwoFAAuthenticationFactory
{
    public function create(PayloadService $payload): PayloadFactory
    {
        $serviceId = 'firewall.two_factor_firewall.' . $this->serviceKey() . '.' . $payload->securityKey->value();

        $this->app->bind($serviceId, function (Application $app) use ($payload) {
            return new TwoFAInterceptor(
                $app->make(Guard::class),
                $app->make($this->registerHandler($payload)),
                $payload->securityKey,
                $app->make(Dispatcher::class),
                $app->make($this->registerEntrypoint($payload))
            );
        });

        return (new PayloadFactory())->setFirewall($serviceId);
    }

    public function position(): string
    {
        return 'pre_auth';
    }

    public function matcher(): ?RequestMatcherInterface
    {
        return $this->formMatcher();
    }

    public function serviceKey(): string
    {
        return 'two-factor-interceptor';
    }
}