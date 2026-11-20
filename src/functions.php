<?php

declare(strict_types=1);

namespace Mercurius\Peer;

/** The text of a key in the language the application chose (English by default). */
function t(string $key): string {
    return Texts::get($key);
}
