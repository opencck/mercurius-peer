<?php

declare(strict_types=1);

namespace Mercurius\Peer;

/** The keys an agent presents to chosen neighbours, by name: an application keeps and makes them. */
interface IdentityKeys {
    /** The key by name; '' — the main one. */
    public function get(string $name): AgentIdentity;
}
