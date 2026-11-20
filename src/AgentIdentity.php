<?php

declare(strict_types=1);

namespace Mercurius\Peer;

use DomainException;

use function Mercurius\Peer\t;

/**
 * An agent's ECDSA key (P-256): made once, kept by the application. Every request and answer between agents is signed
 * with it, so agents tell each other apart by the fingerprint of the public key, not by a shared token.
 *
 * spec: brief/network.md#сеть-агентов-1 — the owner's decision of 2026-11-17: identity by an ECDSA key pair
 */
final class AgentIdentity {
    private function __construct(
        private readonly \OpenSSLAsymmetricKey $private,
        public readonly string $publicKey,
        #[\SensitiveParameter] private readonly string $pem = '',
    ) {}

    /** The private key in PEM, for the application to keep. */
    public function privatePem(): string {
        return $this->pem;
    }

    public static function fromPem(string $pem): self {
        $key = openssl_pkey_get_private($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if ($key === false || $details === false || !isset($details['key']) || !is_string($details['key'])) {
            throw new DomainException(t('peer.agent_identity.klyuch_agenta_ne_chitaetsya'));
        }
        return new self($key, $details['key'], $pem);
    }

    public static function generate(): self {
        return self::fromPem(self::newPem());
    }

    /** A new P-256 key in PEM; where OpenSSL finds no config of its own (PHP on Windows), the one next to PHP is used. */
    private static function newPem(): string {
        $options = ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];
        $env = getenv('OPENSSL_CONF');
        $configs = array_filter([is_string($env) ? $env : null, dirname(PHP_BINARY) . '/extras/ssl/openssl.cnf'], static fn(?string $f): bool => $f !== null && is_file($f));
        foreach ([null, ...$configs] as $config) {
            $key = openssl_pkey_new($config === null ? $options : $options + ['config' => $config]);
            $pem = '';
            if ($key !== false && openssl_pkey_export($key, $pem, null, $config === null ? null : ['config' => $config]) && self::string($pem) !== '') {
                return self::string($pem);
            }
        }
        throw new DomainException(t('peer.agent_identity.ne_udalos_sozdat_klyuch_agenta'));
    }

    public function fingerprint(): string {
        return self::fingerprintOf($this->publicKey) ?? throw new DomainException(t('peer.agent_identity.klyuch_agenta_ne_p_256'));
    }

    /** base64 of the DER signature */
    public function sign(string $data): string {
        $signature = '';
        if (!openssl_sign($data, $signature, $this->private, OPENSSL_ALGO_SHA256) || self::string($signature) === '') {
            throw new DomainException(t('peer.agent_identity.ne_udalos_podpisat'));
        }
        return base64_encode(self::string($signature));
    }

    public static function verify(string $publicKey, string $data, string $signature): bool {
        $key = openssl_pkey_get_public($publicKey);
        $raw = base64_decode($signature, true);
        return $key !== false && $raw !== false && openssl_verify($data, $raw, $key, OPENSSL_ALGO_SHA256) === 1;
    }

    /** sha256 of the DER form of the public key: "SHA256:" and 64 hex digits; null when it is not a P-256 key. */
    public static function fingerprintOf(string $publicKey): ?string {
        $key = openssl_pkey_get_public($publicKey);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        $ec = $details === false || !isset($details['ec']) || !is_array($details['ec']) ? [] : $details['ec'];
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC || ($ec['curve_name'] ?? null) !== 'prime256v1' || !isset($details['key']) || !is_string($details['key'])) {
            return null;
        }
        $der = base64_decode(preg_replace('~-----[^-]+-----|\s+~', '', $details['key']) ?? '', true);
        return $der === false ? null : 'SHA256:' . hash('sha256', $der);
    }

    /** What is signed in a request: method, path, time, a one-time number and the hash of the body. */
    /**
     * @param string $audience the address of the instance the request is for: a request signed for one instance is
     *        no good at another (a neighbour that got it cannot replay it elsewhere)
     */
    public static function requestData(string $method, string $path, string $timestamp, string $nonce, string $body, string $audience): string {
        return implode("\n", ['a2a-request', self::audience($audience), strtoupper($method), $path, $timestamp, $nonce, hash('sha256', $body)]);
    }

    /**
     * The address an instance answers at, in one spelling: scheme, host in lower case, a port only when it is not
     * the default. ws and wss are http and https — the same instance takes both.
     *
     * spec: brief/decisions.md#решения-по-доработкам-2026-11-18 — signatures between agents name the address they are for
     */
    public static function audience(string $url): string {
        $parts = parse_url(trim($url));
        if (!is_array($parts) || !isset($parts['host'])) {
            return '';
        }
        $scheme = match (strtolower($parts['scheme'] ?? 'https')) {
            'ws', 'http' => 'http',
            default => 'https',
        };
        $port = $parts['port'] ?? null;
        $default = $scheme === 'http' ? 80 : 443;
        return $scheme . '://' . strtolower($parts['host']) . ($port === null || $port === $default ? '' : ':' . $port);
    }

    /**
     * What an agent signs in its card when asked with a random number: proof that whoever answers at this address
     * holds the key of the card. Without it a card could carry the key of someone else.
     */
    public static function cardProofData(string $nonce, string $audience): string {
        return implode("\n", ['a2a-card', self::audience($audience), $nonce]);
    }

    /** What is signed in an answer: bound to the request by its one-time number. */
    public static function responseData(string $nonce, string $body): string {
        return implode("\n", ['a2a-response', $nonce, hash('sha256', $body)]);
    }

    /**
     * What the follower signs on a WebSocket handshake: both random numbers and the leader's fingerprint, so the
     * signature serves this connection to this leader only.
     *
     * spec: brief/network.md#вход-по-websocket-и-несколько-ключей-решение-владельца-2026-11-17
     */
    public static function wsServerData(string $clientNonce, string $serverNonce, string $clientFingerprint, string $audience): string {
        return implode("
", ['a2a-ws-server', self::audience($audience), $clientNonce, $serverNonce, $clientFingerprint]);
    }

    /** What the leader signs: the follower's random number first — the phrase it has to prove its key on. */
    public static function wsClientData(string $serverNonce, string $clientNonce, string $serverFingerprint, string $audience): string {
        return implode("
", ['a2a-ws-client', self::audience($audience), $serverNonce, $clientNonce, $serverFingerprint]);
    }

    /** An output of OpenSSL: the analysers type its by-reference results differently. */
    private static function string(mixed $value): string {
        return is_string($value) ? $value : '';
    }
}
