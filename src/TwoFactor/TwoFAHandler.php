<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\TwoFactor;

use Illuminate\Http\Request;
use StephBug\SecurityModel\Application\Exception\InvalidArgument;
use StephBug\SecurityModel\Application\Values\Security\SecurityKey;
use StephBug\SecurityModel\Application\Values\User\EmptyCredentials;
use StephBug\SecurityModel\Guard\Authentication\Token\Tokenable;
use StephBug\SecurityTwoFactor\Application\Http\Request\TwoFAMatcher;
use StephBug\SecurityTwoFactor\Authentication\Token\TwoFactorToken;
use StephBug\SecurityTwoFactor\Authentication\Token\TwoFAToken;
use StephBug\SecurityTwoFactor\User\UserTwoFactor;

class TwoFAHandler
{
    /**
     * @var TwoFAMatcher
     */
    private $matcher;

    /**
     * @var array
     */
    private $supportedToken;

    public function __construct(TwoFAMatcher $matcher, array $supportedToken)
    {
        $this->matcher = $matcher;
        $this->supportedToken = $supportedToken;
    }

    public function createTwoFactorToken(Tokenable $token, Request $request, SecurityKey $securityKey): TwoFactorToken
    {
        if ($token instanceof TwoFactorToken) {
            $token = $token->getSource();
        }

        $credentials = $this->matcher->extract($request);

        return new TwoFAToken($token, $credentials, $securityKey);
    }

    public function initializeToken(Tokenable $token, Request $request, SecurityKey $securityKey): TwoFactorToken
    {
        $this->checkTokenRequirement($token, $securityKey);

        $twoFactorToken = new TwoFAToken($token, new EmptyCredentials(), $securityKey);
        $twoFactorToken->initialize();

        $provider = $token->getUser()->getTwoFactorProvider();

        $twoFactorToken->getTwoFAValue()->setProviderType($provider);
        $twoFactorToken->getTwoFAValue()->setDevice($request->userAgent() ?? 'no device');
        $twoFactorToken->getTwoFAValue()->setIpAddress($request->ip() ?? 'no ip');

        return $twoFactorToken;
    }

    public function supportsToken(Tokenable $token, SecurityKey $securityKey): bool
    {
        foreach ($this->supportedToken as $supportedToken) {
            if ($token instanceof $supportedToken) {
                return $token->getSecurityKey()->sameValueAs($securityKey);
            }
        }

        return false;
    }

    public function supportsUser($user): bool
    {
        return $user instanceof UserTwoFactor && $user->isTwoFactorEnabled();
    }

    public function isTokenStateValid(Tokenable $token): bool
    {
        if ($token instanceof TwoFactorToken) {
            return $token->isInitialized();
        }

        return $token->hasAttribute(TwoFactorToken::TWO_FACTOR_ATTRIBUTE)
            && is_object($token->getAttribute(TwoFactorToken::TWO_FACTOR_ATTRIBUTE));
    }

    private function checkTokenRequirement(Tokenable $token, SecurityKey $securityKey): void
    {
        if (!$this->supportsToken($token, $securityKey)) {
            throw InvalidArgument::reason(
                sprintf('Token %s is not supported by 2FA', get_class($token))
            );
        }

        if (!$this->supportsUser($token->getUser())) {
            throw InvalidArgument::reason(
                sprintf('User must implement %s and 2FA must be enabled by user', UserTwoFactor::class)
            );
        }

        if ($this->isTokenStateValid($token)) {
            throw InvalidArgument::reason('Token must not be already initialized.');
        }
    }
}