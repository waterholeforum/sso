<?php

namespace Waterhole\Sso;

final class Payload
{
    public const NONCE = 'nonce';
    public const RETURN_URL = 'returnUrl';

    public function __construct(private readonly array $payload)
    {
    }

    public static function fromString(string $payload): Payload
    {
        $params = [];

        parse_str(base64_decode(urldecode($payload)), $params);

        return new Payload($params);
    }

    public function getNonce(): ?string
    {
        return $this->get(Payload::NONCE);
    }

    public function getReturnUrl(): ?string
    {
        return $this->get(Payload::RETURN_URL);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->payload[$key] ?? $default;
    }
}
