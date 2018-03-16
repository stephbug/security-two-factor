<?php

return [
    'providers' => [
        'qr_code' => [
            'service' => \StephBug\SecurityTwoFactor\TwoFactor\Providers\Google2FAProvider::class
        ]
    ]
];