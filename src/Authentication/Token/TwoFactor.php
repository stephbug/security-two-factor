<?php

declare(strict_types=1);

namespace StephBug\SecurityTwoFactor\Authentication\Token;

class TwoFactor implements \JsonSerializable
{
    /**
     * @var string
     */
    private $providerType;

    /**
     * @var string
     */
    private $device;

    /**
     * @var string
     */
    private $ipAddress;

    /**
     * @var bool
     */
    private $authenticated = false;

    public function getProviderType(): string
    {
        return $this->providerType;
    }

    public function setProviderType(string $providerType): void
    {
        $this->providerType = $providerType;
    }

    public function isAuthenticated(): bool
    {
        return $this->authenticated;
    }

    public function setAuthenticated(bool $authenticated): void
    {
        $this->authenticated = $authenticated;
    }

    public function getDevice(): string
    {
        return $this->device;
    }

    public function setDevice(string $device): void
    {
        $this->device = $device;
    }

    public function setIpAddress(string $ipAddress): void
    {
        $this->ipAddress = $ipAddress;
    }

    public function getIpAddress(): string
    {
        return $this->ipAddress;
    }

    public function toArray(): array
    {
        return [
            'providerType' => $this->providerType,
            'authenticated' => $this->authenticated,
            'device' => $this->device,
            'ipAddress' => $this->ipAddress
        ];
    }

    public function __toString(): string
    {
        return $this->toJson();
    }

    public function jsonSerialize()
    {
        return $this->toArray();
    }

    public function toJson(): string
    {
        return json_encode($this->jsonSerialize());
    }
}