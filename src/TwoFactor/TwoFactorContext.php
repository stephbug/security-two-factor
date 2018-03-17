<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\TwoFactor;

use StephBug\SecurityModel\Application\Exception\InvalidArgument;

class TwoFactorContext
{
    /**
     * @var array
     */
    private $context;

    public function __construct(array $context)
    {
        $this->context = $context;
    }

    public function safe(string $key): string
    {
        return $this->fromContext($key, 'safe');
    }

    public function login(string $key): string
    {
        return $this->fromContext($key, 'login');
    }

    public function loginPost(string $key): string
    {
        return $this->fromContext($key, 'login_post');
    }

    public function success(string $key): string
    {
        return $this->fromContext($key, 'success');
    }

    public function excludedRoutes(string $key): array
    {
        return $this->fromContext($key, 'excluded_routes');
    }

    public function supportedToken(string $key): array
    {
        return $this->fromContext($key, 'supported_token');
    }

    protected function fromContext(string $key, string $name)
    {
        if (!isset($this->context[$key])) {
            $key = 'default';
        }

        if (!isset($this->context[$key])) {
            throw InvalidArgument::reason('Missing Two factor context key in config');
        }

        return $this->context[$key][$name];
    }
}