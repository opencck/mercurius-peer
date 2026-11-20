<?php

declare(strict_types=1);

namespace Mercurius\Peer\Test;

use Amp\Cancellation;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Amp\PHPUnit\AsyncTestCase;
use DomainException;
use Mercurius\Peer\A2a;
use Mercurius\Peer\A2aClient;
use Mercurius\Peer\AgentIdentity;
use Mercurius\Peer\PeerEndpoint;
use RuntimeException;

final class PeerTest extends AsyncTestCase {
    /** @param array<array-key, mixed>|null $card */
    private static function peer(?array $card): PeerEndpoint {
        return new class ($card) implements PeerEndpoint {
            /** @param array<array-key, mixed>|null $card */
            public function __construct(private readonly ?array $card) {}

            public function peerName(): string {
                return 'doorotar';
            }

            public function peerUrl(): string {
                return 'https://doorotar.example.com';
            }

            public function peerPublicKey(): string {
                return '';
            }

            public function peerCard(): ?array {
                return $this->card;
            }

            public function peerIdentity(): string {
                return '';
            }
        };
    }

    public function testAKeySignsAndOnlyItsSignatureOfTheSameDataPasses(): void {
        $one = AgentIdentity::generate();
        $other = AgentIdentity::generate();
        $data = AgentIdentity::requestData('POST', '/a2a', '1700000000', 'nonce', '{"a":1}', 'https://doorotar.example.com');

        $signature = $one->sign($data);

        self::assertTrue(AgentIdentity::verify($one->publicKey, $data, $signature));
        self::assertFalse(AgentIdentity::verify($one->publicKey, $data . ' ', $signature), 'changed data');
        self::assertFalse(AgentIdentity::verify($other->publicKey, $data, $signature), 'another key');
        self::assertMatchesRegularExpression('~^SHA256:[0-9a-f]{64}$~', $one->fingerprint());
        self::assertSame($one->fingerprint(), AgentIdentity::fromPem($one->privatePem())->fingerprint(), 'kept and read back');
    }

    public function testAKeyThatIsNotOneIsRefused(): void {
        $this->expectException(DomainException::class);
        AgentIdentity::fromPem('not a key');
    }

    public function testTheProtocolHelpers(): void {
        self::assertSame('a' . "\n" . 'b', A2a::text(['parts' => [['text' => 'a'], ['kind' => 'file'], ['text' => 'b']]]));
        self::assertSame('_etc_passwd', A2a::fileName('/etc/passwd'));
        self::assertSame('file', A2a::fileName(' .. '));
        self::assertSame('_', A2a::fileName("..\x00"), 'a control character becomes _');
        self::assertSame('image/png', A2a::mediaType('', 'a.PNG'));
        self::assertSame('text/plain', A2a::mediaType('text/plain', 'a.bin'));
        self::assertSame(['jsonrpc' => '2.0', 'id' => 3, 'error' => ['code' => A2a::ERR_UNAUTHORIZED, 'message' => 'no']], A2a::error(3, A2a::ERR_UNAUTHORIZED, 'no'));
        [$type, $body] = A2a::multipart([['name' => 'a"b.txt', 'bytes' => 'hi']]);
        self::assertStringStartsWith('multipart/form-data; boundary=', $type);
        self::assertStringContainsString('filename="a_b.txt"', $body);
        self::assertStringContainsString("Content-Type: text/plain\r\n\r\nhi\r\n", $body);
    }

    public function testTheCardSaysTheTransport(): void {
        self::assertSame('ws', A2aClient::transport(self::peer(['mercurius' => ['transport' => 'ws', 'ws' => 'wss://doorotar.example.com/a2a/ws']])));
        self::assertSame('wss://doorotar.example.com/a2a/ws', A2aClient::socketUrl(self::peer(['mercurius' => ['ws' => 'wss://doorotar.example.com/a2a/ws']])));
        self::assertSame('http', A2aClient::transport(self::peer(null)), 'a neighbour added before its card said it');
        self::assertSame('mercurius-doorotar', A2aClient::nameOfUrl('https://mercurius-doorotar.srv.example.com/'));
    }

    public function testACardCountsOnlyWhenItProvesItsKey(): void {
        $neighbour = AgentIdentity::generate();
        $base = 'https://doorotar.example.com';
        $proving = new CardHttpFake(static function (string $nonce) use ($neighbour, $base): array {
            return ['name' => 'doorotar', 'mercurius' => ['publicKey' => $neighbour->publicKey, 'proof' => $neighbour->sign(AgentIdentity::cardProofData($nonce, $base))]];
        });
        $client = new A2aClient(new HttpClient($proving, []), AgentIdentity::generate());
        self::assertSame('doorotar', $client->provenCard($base)['name'] ?? null);

        // a card copied from another agent: its proof was made for another number
        $copied = new CardHttpFake(static function (string $nonce) use ($neighbour, $base): array {
            return ['name' => 'doorotar', 'mercurius' => ['publicKey' => $neighbour->publicKey, 'proof' => $neighbour->sign(AgentIdentity::cardProofData('old', $base))]];
        });
        $this->expectException(RuntimeException::class);
        (new A2aClient(new HttpClient($copied, []), AgentIdentity::generate()))->provenCard($base);
    }
}

/** Serves an agent card made for the nonce of the request. */
final class CardHttpFake implements DelegateHttpClient {
    /** @param \Closure(string): array<string, mixed> $card */
    public function __construct(private readonly \Closure $card) {}

    public function request(Request $request, Cancellation $cancellation): Response {
        parse_str($request->getUri()->getQuery(), $query);
        $nonce = isset($query['nonce']) && is_string($query['nonce']) ? $query['nonce'] : '';
        return new Response('1.1', 200, null, ['content-type' => 'application/json'], json_encode(($this->card)($nonce), JSON_THROW_ON_ERROR), $request);
    }
}
