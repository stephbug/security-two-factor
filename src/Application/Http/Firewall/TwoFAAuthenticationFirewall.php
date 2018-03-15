<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Firewall;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Http\Event\UserLogin;
use StephBug\SecurityModel\Application\Values\SecurityKey;
use StephBug\SecurityModel\Guard\Guard;

class TwoFAAuthenticationFirewall
{
    /**
     * @var Guard
     */
    private $guard;

    /**
     * @var SecurityKey
     */
    private $securityKey;

    /**
     * @var Dispatcher
     */
    private $events;

    public function __construct(Guard $guard, SecurityKey $securityKey, Dispatcher $events)
    {
        $this->guard = $guard;
        $this->securityKey = $securityKey;
        $this->events = $events;
    }

    public function handle(Request $request, \Closure $next)
    {
        $this->events->listen(UserLogin::class, [$this, 'onUserLogin']);

        $response = $next($request);
    }
}