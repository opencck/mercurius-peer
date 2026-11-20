<?php

declare(strict_types=1);

namespace Mercurius\Peer;

/**
 * A neighbouring agent as the client sees it: its name here, its address, the public key pinned for it, its card and
 * the name of the key this agent presents to it ('' — the main key). An application implements it on its own record.
 */
interface PeerEndpoint {
    public function peerName(): string;

    public function peerUrl(): string;

    /** PEM of the neighbour's P-256 public key: an answer counts only when signed by it */
    public function peerPublicKey(): string;

    /** @return array<array-key, mixed>|null */
    public function peerCard(): ?array;

    public function peerIdentity(): string;
}
