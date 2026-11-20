<?php

declare(strict_types=1);

namespace Mercurius\Peer;

use Amp\Cancellation;
use Amp\CancelledException;
use Amp\CompositeCancellation;
use Amp\DeferredFuture;
use Amp\NullCancellation;
use Amp\TimeoutCancellation;
use RuntimeException;
use Throwable;

use function Amp\async;
use function Mercurius\Peer\t;

/**
 * The leader's end of a connection to a neighbour: the handshake (the leader's key and number, the neighbour's number
 * signed by the neighbour and checked against its pinned key, the neighbour's number signed by the leader), then
 * JSON-RPC requests matched by id. Frames are read all the time in a fiber of their own, so the neighbour never stalls
 * on a full connection; a closed connection fails what waits. The connection goes both ways: a frame with a method is a
 * request of the other side, answered by the given handler (the other side's tasks for this agent); none — refused.
 *
 * spec: BRIEF.md#подключения-агентов-решение-владельца-2026-11-17
 *
 * spec: BRIEF.md#вход-по-websocket-и-несколько-ключей-решение-владельца-2026-11-17
 */
final class A2aSocket {
    /**
     * The version of the handshake: 2 — both signatures name the address dialed. An agent of another version is
     * turned away with this said, not with a signature that does not match.
     *
     * spec: BRIEF.md#решения-по-доработкам-2026-11-18
     */
    public const VERSION = 2;

    private int $nextId = 1;
    /** @var array<int, DeferredFuture<array<array-key, mixed>>> */
    private array $pending = [];
    private bool $closed = false;
    /** @var \Amp\Future<void> the reading of frames: it ends when the connection closes */
    private readonly \Amp\Future $reading;
    public float $lastUsed;
    public int $requests = 0;
    /** @var (\Closure(string, array<array-key, mixed>): void)|null told of a notice of the other side: a method, no id */
    private ?\Closure $notice = null;

    /** @param (\Closure(array<array-key, mixed>): array<string, mixed>)|null $serve answers a request of the other side */
    private function __construct(private readonly A2aChannel $channel, private readonly ?\Closure $serve = null) {
        $this->lastUsed = microtime(true);
        $this->reading = async($this->read(...));
        $this->reading->ignore();
    }

    /**
     * The follower's end once the leader proved its key: requests of the leader go to $serve.
     *
     * @param \Closure(array<array-key, mixed>): array<string, mixed> $serve
     */
    public static function accepted(A2aChannel $channel, \Closure $serve): self {
        return new self($channel, $serve);
    }

    /** Waits until the connection closes. */
    public function join(): void {
        $this->reading->await();
    }

    /**
     * @param (\Closure(array<array-key, mixed>): array<string, mixed>)|null $serve answers requests of the neighbour
     * @param array{name?: string, url?: string} $about what this agent tells of itself: a neighbour that does not know
     *        it yet shows this to its owner
     * @param string $audience the address this agent dialed: both signatures of the handshake name it, so a handshake
     *        relayed by another instance does not hold at either end
     * @throws RuntimeException the neighbour refused, or it is not who its pinned key says
     */
    public static function open(A2aChannel $channel, AgentIdentity $me, string $peerKey, float $timeout = 10.0, ?\Closure $serve = null, array $about = [], string $audience = ''): self {
        $deadline = new TimeoutCancellation($timeout);
        $nonce = bin2hex(random_bytes(16));
        try {
            $channel->send(json_encode(['type' => 'hello', 'version' => self::VERSION, 'key' => $me->publicKey, 'nonce' => $nonce] + $about, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            $challenge = self::frame($channel->receive($deadline));
            if (($challenge['type'] ?? null) === 'denied') {
                throw new RuntimeException(t('peer.a2a_client.sosed_ne_pustil') . self::reason($challenge));
            }
            $serverNonce = isset($challenge['nonce']) && is_string($challenge['nonce']) ? $challenge['nonce'] : '';
            $signature = isset($challenge['signature']) && is_string($challenge['signature']) ? $challenge['signature'] : '';
            $peerFingerprint = AgentIdentity::fingerprintOf($peerKey) ?? '';
            if (($challenge['type'] ?? null) !== 'challenge' || $serverNonce === ''
                || !AgentIdentity::verify($peerKey, AgentIdentity::wsServerData($nonce, $serverNonce, $me->fingerprint(), $audience), $signature)) {
                throw new RuntimeException(t('peer.a2a_client.otvet_podpisan_ne_klyuchom_etogo'));
            }
            $channel->send(json_encode(['type' => 'auth', 'signature' => $me->sign(AgentIdentity::wsClientData($serverNonce, $nonce, $peerFingerprint, $audience))], JSON_THROW_ON_ERROR));
            $ready = self::frame($channel->receive($deadline));
            if (($ready['type'] ?? null) !== 'ready') {
                throw new RuntimeException(t('peer.a2a_client.sosed_ne_pustil') . self::reason($ready));
            }
        } catch (CancelledException) {
            $channel->close();
            throw new RuntimeException(t('peer.a2a_client.sosed_ne_otvetil') . 'handshake).');
        } catch (RuntimeException $e) {
            $channel->close();
            throw $e;
        }
        return new self($channel, $serve);
    }

    /**
     * @param array<string, mixed> $params
     * @return array<array-key, mixed> the result
     * @throws RuntimeException
     */
    public function request(string $method, array $params, ?Cancellation $cancellation = null, float $timeout = 30.0): array {
        if ($this->closed) {
            throw new RuntimeException(t('peer.a2a_client.sosed_ne_otvetil') . 'closed).');
        }
        $id = $this->nextId++;
        $this->lastUsed = microtime(true);
        $this->requests++;
        /** @var DeferredFuture<array<array-key, mixed>> $deferred */
        $deferred = new DeferredFuture();
        $this->pending[$id] = $deferred;
        try {
            $this->channel->send(json_encode(['jsonrpc' => '2.0', 'id' => $id, 'method' => $method, 'params' => (object) $params], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE));
            $answer = $deferred->getFuture()->await(new CompositeCancellation($cancellation ?? new NullCancellation(), new TimeoutCancellation($timeout)));
        } catch (CancelledException) {
            throw new RuntimeException(t('peer.a2a_client.sosed_ne_otvetil') . 'timeout).');
        } catch (RuntimeException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new RuntimeException(t('peer.a2a_client.sosed_ne_otvetil') . (new \ReflectionClass($e))->getShortName() . ').');
        } finally {
            unset($this->pending[$id]);
        }
        if (isset($answer['error']) && is_array($answer['error'])) {
            $message = isset($answer['error']['message']) && is_string($answer['error']['message']) ? $answer['error']['message'] : 'error';
            throw new RuntimeException(t('peer.a2a_client.sosed_otkazal') . mb_substr($message, 0, 200));
        }
        return isset($answer['result']) && is_array($answer['result']) ? $answer['result'] : throw new RuntimeException(t('peer.a2a_client.sosed_otvetil_bez_rezultata'));
    }

    /**
     * A notice to the other side: a JSON-RPC notification, no answer. Lost when the connection is gone — the other side
     * still polls.
     *
     * spec: BRIEF.md#сеть-агентов — the end of a task is pushed over a live connection
     * @param array<string, mixed> $params
     */
    public function notify(string $method, array $params): void {
        if ($this->closed) {
            return;
        }
        try {
            $this->channel->send(json_encode(['jsonrpc' => '2.0', 'method' => $method, 'params' => (object) $params], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE));
        } catch (Throwable) {
            // the connection is gone
        }
    }

    /** @param \Closure(string, array<array-key, mixed>): void $notice */
    public function onNotice(\Closure $notice): void {
        $this->notice = $notice;
    }

    public function alive(): bool {
        return !$this->closed && !$this->channel->isClosed();
    }

    public function close(): void {
        $this->channel->close();
        $this->fail();
    }

    private function read(): void {
        try {
            while (($frame = $this->channel->receive()) !== null) {
                $message = self::frame($frame);
                if (isset($message['method']) && !array_key_exists('id', $message)) {
                    // a notice of the other side: nothing is answered
                    $method = is_string($message['method']) ? $message['method'] : '';
                    $params = isset($message['params']) && is_array($message['params']) ? $message['params'] : [];
                    $notice = $this->notice;
                    if ($notice !== null && $method !== '') {
                        async(static fn() => $notice($method, $params))->ignore();
                    }
                    continue;
                }
                if (isset($message['method'])) {
                    // a request of the other side: answered in its own fiber, reading goes on
                    $this->lastUsed = microtime(true);
                    async(fn() => $this->answer($message))->ignore();
                    continue;
                }
                /** @var mixed $id */
                $id = $message['id'] ?? null;
                if (!is_int($id)) {
                    continue;
                }
                $waiting = $this->pending[$id] ?? null;
                if ($waiting !== null) {
                    unset($this->pending[$id]);
                    $waiting->complete($message);
                }
            }
        } catch (Throwable) {
            // the connection broke: what waits fails below
        }
        $this->fail();
    }

    /** @param array<array-key, mixed> $request */
    private function answer(array $request): void {
        /** @var mixed $id */
        $id = $request['id'] ?? null;
        $answer = $this->serve === null
            ? A2a::error($id, A2a::ERR_UNAUTHORIZED, 'this agent takes no requests on this connection')
            : ($this->serve)($request);
        try {
            $this->channel->send(json_encode($answer, JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        } catch (Throwable) {
            // the connection is gone
        }
    }

    private function fail(): void {
        $this->closed = true;
        $pending = $this->pending;
        $this->pending = [];
        foreach ($pending as $deferred) {
            $deferred->error(new RuntimeException(t('peer.a2a_client.sosed_ne_otvetil') . 'closed).'));
        }
    }

    /** @param array<array-key, mixed> $frame */
    private static function reason(array $frame): string {
        return isset($frame['reason']) && is_string($frame['reason']) ? mb_substr($frame['reason'], 0, 300) : '';
    }

    /** @return array<array-key, mixed> */
    private static function frame(?string $text): array {
        try {
            /** @var mixed $data */
            $data = $text === null ? null : json_decode($text, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return [];
        }
        return is_array($data) ? $data : [];
    }
}
