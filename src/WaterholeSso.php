<?php

namespace Waterhole\Sso;

final class WaterholeSso
{
    public function __construct(private readonly string $secret)
    {
    }

    public function authenticate(
        PendingUser $user,
        string $payload = null,
        string $sig = null,
    ): never {
        $payload ??= $_GET['payload'] ?? null;
        $sig ??= $_GET['sig'] ?? null;

        if (!$this->validate($payload, $sig)) {
            header('HTTP/1.1 403 Forbidden');
            die('Invalid SSO payload');
        }

        $payload = $this->parse($payload);
        $nonce = $payload->getNonce();
        $url = $payload->getReturnUrl();

        $query = $this->buildQuery($nonce, get_object_vars($user));

        header("Location: $url?$query");
        exit();
    }

    public function validate(string $payload, string $sig): bool
    {
        $payload = urldecode($payload);

        return $this->sign($payload) === $sig;
    }

    public function parse(string $payload): Payload
    {
        return Payload::fromString($payload);
    }

    public function buildQuery(string $nonce, array $data): string
    {
        $payload = base64_encode(http_build_query([Payload::NONCE => $nonce] + $data));

        $sig = $this->sign($payload);

        return http_build_query(compact('payload', 'sig'));
    }

    private function sign($payload): string
    {
        return hash_hmac('sha256', $payload, $this->secret);
    }
}
