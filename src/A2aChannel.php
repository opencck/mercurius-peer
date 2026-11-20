<?php

declare(strict_types=1);

namespace Mercurius\Peer;

use Amp\Cancellation;

/**
 * Text frames between two agents over one connection (a WebSocket): the handshake that proves the keys, then JSON-RPC.
 *
 * spec: brief/network.md#вход-по-websocket-и-несколько-ключей
 */
interface A2aChannel {
    public function send(string $text): void;

    /** The next frame; null — the connection closed. */
    public function receive(?Cancellation $cancellation = null): ?string;

    public function close(): void;

    public function isClosed(): bool;
}
