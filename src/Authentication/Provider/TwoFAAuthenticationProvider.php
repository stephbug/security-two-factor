<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Authentication\Provider;

use StephBug\SecurityModel\Application\Exception\UnsupportedProvider;
use StephBug\SecurityModel\Application\Exception\UnsupportedUser;
use StephBug\SecurityModel\Application\Values\SecurityKey;
use StephBug\SecurityModel\Guard\Authentication\Providers\AuthenticationProvider;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use StephBug\SecurityModel\User\Exception\BadCredentials;
use StephBug\SecurityTwoFactor\Application\Values\TwoFactorCredentialsWithConfirmation;
use StephBug\SecurityTwoFactor\Authentication\Token\TwoFactorToken;
use StephBug\SecurityTwoFactor\TwoFactor\TwoFactorProviderFactory;
use StephBug\SecurityTwoFactor\User\UserTwoFactor;

class TwoFAAuthenticationProvider implements AuthenticationProvider
{
    /**
     * @var TwoFactorProviderFactory
     */
    private $factory;

    /**
     * @var SecurityKey
     */
    private $securityKey;

    public function __construct(TwoFactorProviderFactory $factory, SecurityKey $securityKey)
    {
        $this->factory = $factory;
        $this->securityKey = $securityKey;
    }

    public function authenticate(Tokenable $token): Tokenable
    {
        /** @var TwoFactorToken $token */
        $user = $this->retrieveUser($token);

        $credentials = TwoFactorCredentialsWithConfirmation::withSecret(
            $token->getCredentials()->credentials(),
            $user->getTwoFactorUserSecret()
        );

        $provider = $this->factory->make($user->getTwoFactorProvider());

        if (!$provider->isCredentialsValid($credentials)) {
            throw BadCredentials::invalid($credentials);
        }

        return $token->getSource();
    }

    protected function retrieveUser(Tokenable $token): UserTwoFactor
    {
        /** @var TwoFactorToken $token */
        if (!$this->supports($token)) {
            throw UnsupportedProvider::withSupport($token, $this);
        }

        $user = $token->getUser();

        if (!$user instanceof UserTwoFactor || !$user->isTwoFactorEnabled()) {
            throw UnsupportedUser::withUser($user);
        }

        if ($token->getTwoFAValue()->getProviderType() !== $user->getTwoFactorProvider()) {
            logger('Two factor provider does not match between token and user');
        }

        return $user;
    }

    public function supports(Tokenable $token): bool
    {
        return $token instanceof TwoFactorToken && $token->getSecurityKey()->sameValueAs($this->securityKey);
    }
}