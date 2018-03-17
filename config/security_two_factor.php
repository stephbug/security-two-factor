<?php

return [
    'providers' => [
        'qr_code' => [
            'service' => \StephBug\SecurityTwoFactor\TwoFactor\Providers\Google2FAProvider::class
        ]
    ],

    'context' => [

        'default' => [
            'login' => 'front.auth.two_factor_login',
            'login_post' => 'front.auth.two_factor_login.post',
            'safe' => 'home',
            'success' => 'home',
            'excluded_routes' => [
                'front.auth.logout'
            ],
            'supported_token' => [
                \StephBug\SecurityModel\Guard\Authentication\Token\IdentifierPasswordToken::class,
                \StephBug\SecurityModel\Guard\Authentication\Token\RecallerToken::class
            ]
        ]
    ]
];