<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Application\Http\Firewall;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Exception\InvalidArgument;
use StephBug\SecurityModel\Application\Http\Entrypoint\Entrypoint;
use StephBug\SecurityModel\Application\Http\Event\UserLogin;
use StephBug\SecurityModel\Application\Values\SecurityKey;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use StephBug\SecurityModel\Guard\Guard;
use StephBug\SecurityTwoFactor\TwoFactor\TwoFAHandler;
use Symfony\Component\HttpFoundation\Response;

class TwoFAInterceptor
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

    /**
     * @var TwoFAHandler
     */
    private $twoFAHandler;

    /**
     * @var UserLogin
     */
    private $event;

    /**
     * @var Entrypoint
     */
    private $entrypoint;

    public function __construct(Guard $guard,
                                TwoFAHandler $twoFAHandler,
                                SecurityKey $securityKey,
                                Dispatcher $events,
                                Entrypoint $entrypoint)
    {
        $this->guard = $guard;
        $this->securityKey = $securityKey;
        $this->events = $events;
        $this->twoFAHandler = $twoFAHandler;
        $this->entrypoint = $entrypoint;
    }

    public function handle(Request $request, \Closure $next)
    {
        $this->events->listen(UserLogin::class, [$this, 'onUserLogin']);

        $response = $next($request);
        $token = $this->guard->storage()->getToken();

        if (!$response instanceof Response || $response = $this->canNotHandleResponse($response, $token)) {
            return $response;
        }

        return $this->respondWithTwoFactor($token, $request);
    }

    protected function respondWithTwoFactor(Tokenable $token, Request $request): Response
    {
        $twoFAToken = $this->twoFAHandler->initializeToken($token, $request, $this->securityKey);

        //event initialized

        $this->guard->put($twoFAToken->getSource());

        return $this->entrypoint->startAuthentication($request);
    }

    protected function canNotHandleResponse(Response $response, Tokenable $token = null): ?Response
    {
        if (!$this->event) {
            return $response;
        }

        if (!$token || !$this->twoFAHandler->supportsToken($token, $this->securityKey)) {
            return $response;
        }

        if ($token !== $this->event->token()) {
            throw InvalidArgument::reason(
                'Token from storage and token from user login event must be equals
                to be handled by the security Two Factor'
            );
        }

        return !$this->twoFAHandler->supportsUser($this->event->token()->getUser())
            ? $response : null;
    }

    public function onUserLogin(UserLogin $event): void
    {
        $this->event = $event;
    }

    protected function requireAuthentication(Request $request): bool
    {
        if ($token = $this->guard->storage()->getToken()) {
            return $this->twoFAHandler->supportsToken($token, $this->securityKey);
        }

        return true;
    }
}