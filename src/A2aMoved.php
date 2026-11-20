<?php

declare(strict_types=1);

namespace Mercurius\Peer;

use RuntimeException;

/** The neighbour has no such entrance (it changed its transport): its card is read again. */
final class A2aMoved extends RuntimeException {}
