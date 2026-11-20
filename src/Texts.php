<?php

declare(strict_types=1);

namespace Mercurius\Peer;

use Closure;

/**
 * What the client says in its errors, by key. English from resources/texts.en.php by default; an application gives its
 * own translator once at the start.
 */
final class Texts {
    /** @var (Closure(string): string)|null */
    private static ?Closure $translate = null;
    /** @var array<string, string>|null */
    private static ?array $english = null;

    /** @param (Closure(string): string)|null $translate the text of a key; null — back to English */
    public static function translateWith(?Closure $translate): void {
        self::$translate = $translate;
    }

    public static function get(string $key): string {
        if (self::$translate !== null) {
            return (self::$translate)($key);
        }
        if (self::$english === null) {
            /** @var array<string, string> $catalog */
            $catalog = require dirname(__DIR__) . '/resources/texts.en.php';
            self::$english = $catalog;
        }
        return self::$english[$key] ?? $key;
    }
}
