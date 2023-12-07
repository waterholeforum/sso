<?php

namespace Waterhole\Sso;

class PendingUser
{
    public function __construct(
        public string $identifier,
        public string $email,
        public ?string $name = null,
        public ?string $avatar = null,
        public ?array $groups = null,
    ) {
    }
}
