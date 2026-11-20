<?php

declare(strict_types=1);

namespace Mercurius\Peer;

/**
 * What both sides of A2A share: the JSON-RPC error codes of the entrance, the limits and the address scheme of files
 * sent ahead of a message, the text of a message and the form of an upload.
 */
final class A2a {
    public const ERR_UNAUTHORIZED = -32050;
    public const ERR_RATE_LIMITED = -32051;

    /** a file and all files of one message, as Telegram */
    public const FILE_MAX = 20_000_000;
    public const COUNT_MAX = 10;
    /** the body of an upload: the files and the multipart overhead */
    public const BODY_MAX = 21_000_000;
    /** a file sent ahead by POST /a2a/files is named in the message by this scheme and its id */
    public const SCHEME = 'a2a-file:';

    /** @return array{jsonrpc: string, id: mixed, error: array{code: int, message: string}} */
    public static function error(mixed $id, int $code, string $message): array {
        return ['jsonrpc' => '2.0', 'id' => $id, 'error' => ['code' => $code, 'message' => $message]];
    }

    /**
     * The text parts of a message, joined.
     *
     * @param array<array-key, mixed> $message
     */
    public static function text(array $message): string {
        $texts = [];
        /** @var mixed $part */
        foreach (isset($message['parts']) && is_array($message['parts']) ? $message['parts'] : [] as $part) {
            if (is_array($part) && isset($part['text']) && is_string($part['text'])) {
                $texts[] = $part['text'];
            }
        }
        return trim(implode("\n", $texts));
    }

    /** A file name another agent gave: no control characters or path separators, up to 100 characters. */
    public static function fileName(string $name): string {
        $clean = preg_replace('~[\x00-\x1F\x7F/\\\\]+~u', '_', $name) ?? '';
        $clean = trim(mb_substr($clean, 0, 100), ". \t");
        return $clean === '' ? 'file' : $clean;
    }

    /** The type the sender gave when it is a plain media type, else by the extension. */
    public static function mediaType(string $given, string $name): string {
        $given = strtolower(trim($given));
        if ($given !== '' && $given !== 'application/octet-stream' && preg_match('~^[a-z]+/[a-z0-9.+-]{1,100}$~', $given) === 1) {
            return $given;
        }
        return match (strtolower(pathinfo($name, PATHINFO_EXTENSION))) {
            'jpg', 'jpeg' => 'image/jpeg', 'png' => 'image/png', 'webp' => 'image/webp', 'gif' => 'image/gif',
            'mp3' => 'audio/mpeg', 'ogg', 'oga', 'opus' => 'audio/ogg', 'm4a' => 'audio/mp4', 'wav' => 'audio/wav',
            'mp4' => 'video/mp4', 'webm' => 'video/webm', 'mov' => 'video/quicktime',
            'pdf' => 'application/pdf', 'txt', 'log' => 'text/plain', 'md' => 'text/markdown', 'csv' => 'text/csv',
            'json' => 'application/json', 'html', 'htm' => 'text/html', 'xml' => 'application/xml',
            'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'zip' => 'application/zip',
            default => 'application/octet-stream',
        };
    }

    /**
     * A multipart/form-data body of files, for an upload to a neighbour.
     *
     * @param list<array{name: string, bytes: string, mediaType?: string}> $files
     * @return array{string, string} [content type, body]
     */
    public static function multipart(array $files): array {
        $boundary = '----mercurius' . bin2hex(random_bytes(12));
        $body = '';
        foreach ($files as $index => $file) {
            $name = str_replace(['"', "\r", "\n", '\\'], '_', $file['name']);
            $body .= '--' . $boundary . "\r\n"
                . 'Content-Disposition: form-data; name="file' . $index . '"; filename="' . $name . '"' . "\r\n"
                . 'Content-Type: ' . self::mediaType($file['mediaType'] ?? '', $file['name']) . "\r\n\r\n"
                . $file['bytes'] . "\r\n";
        }
        return ['multipart/form-data; boundary=' . $boundary, $body . '--' . $boundary . "--\r\n"];
    }
}
