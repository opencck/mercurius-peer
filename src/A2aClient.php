<?php

declare(strict_types=1);

namespace Mercurius\Peer;

use Amp\Cancellation;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\Request;
use RuntimeException;
use SensitiveParameter;
use Throwable;

use function Mercurius\Peer\t;

/**
 * Talks to a neighbouring agent over A2A v1.0: its card, a task, the state of a task. The transport is the one the
 * neighbour's card names: WebSocket (one connection, the keys proved once by the handshake) or HTTP (each request
 * signed). This agent presents to each neighbour the key chosen for it; an answer counts only when it comes from the
 * key pinned for the neighbour. Errors carry no token.
 *
 * spec: brief/network.md#вход-по-websocket-и-несколько-ключей-решение-владельца-2026-11-17
 *
 * spec: brief/network.md#сеть-агентов-1
 * ref: references/hermes-agent/plugins/platforms/a2a/tools.py@e96221fa:L146-L254 — discover, call and check a remote
 *      agent; here without streaming: the leader polls GetTask
 */
final class A2aClient {
    /** @var array<string, A2aSocket> open connections by neighbour and key */
    private array $sockets = [];

    /** @param (\Closure(string, string): A2aChannel)|null $connect opens a WebSocket by its url with the entrance token */
    public function __construct(
        private readonly HttpClient $http,
        private readonly AgentIdentity $identity,
        private readonly ?IdentityKeys $keys = null,
        private readonly ?\Closure $connect = null,
        /** live connections with other agents, in both directions */
        private readonly ?A2aLinks $links = null,
        /** @var (\Closure(string, string, string): ((\Closure(array<array-key, mixed>): array<string, mixed>)|null))|null who answers the neighbour's requests: by its key, name and address */
        private readonly ?\Closure $serveFor = null,
        /** the public address of this agent: a neighbour that does not know it yet shows it and its name to its owner */
        private readonly string $self = '',
        /** http — files go ahead by POST /a2a/files; ws — as bytes in the message over a WebSocket */
        public readonly string $fileTransport = 'http',
    ) {}

    /**
     * What this agent tells of itself on the way in: a name (the first label of its host) and its address.
     *
     * spec: brief/network.md#незнакомый-агент-стучится-решение-владельца-2026-11-17
     *
     * @return array{name?: string, url?: string}
     */
    public function about(): array {
        return $this->self === '' || !str_starts_with($this->self, 'http') ? [] : ['name' => self::nameOfUrl($this->self), 'url' => $this->self];
    }

    /** The first label of the host of an address: what an instance calls itself to a neighbour. */
    public static function nameOfUrl(string $url): string {
        $host = parse_url($url, PHP_URL_HOST);
        return is_string($host) ? explode('.', $host)[0] : '';
    }

    /** ws — the neighbour's card names a WebSocket; http otherwise (neighbours added before the card said it). */
    public static function transport(PeerEndpoint $peer): string {
        $meta = isset($peer->peerCard()['mercurius']) && is_array($peer->peerCard()['mercurius']) ? $peer->peerCard()['mercurius'] : [];
        return ($meta['transport'] ?? null) === 'ws' && isset($meta['ws']) && is_string($meta['ws']) ? 'ws' : 'http';
    }

    /** The WebSocket address the neighbour's card names; '' — none. */
    public static function socketUrl(PeerEndpoint $peer): string {
        $card = $peer->peerCard() ?? [];
        /** @var mixed $meta */
        $meta = $card['mercurius'] ?? null;
        /** @var mixed $url */
        $url = is_array($meta) ? ($meta['ws'] ?? null) : null;
        return is_string($url) ? $url : '';
    }

    /** Opens a connection to the neighbour now, or finds a live one. */
    public function connect(PeerEndpoint $peer, #[SensitiveParameter] string $token): A2aSocket {
        return $this->socket($peer, $token);
    }

    /**
     * A request over a live connection with an agent that is not a neighbour of this agent but connected here.
     *
     * @param array<string, mixed> $params
     * @return array<array-key, mixed>
     */
    public static function over(A2aSocket $socket, string $method, array $params, ?Cancellation $cancellation = null): array {
        return $socket->request($method, $params, $cancellation);
    }

    /** The key this agent presents to the neighbour. */
    public function identityFor(PeerEndpoint $peer): AgentIdentity {
        return $this->keys?->get($peer->peerIdentity()) ?? $this->identity;
    }

    /** @return array<array-key, mixed> */
    public function card(string $base, ?Cancellation $cancellation = null): array {
        return $this->request(new Request(rtrim($base, '/') . '/.well-known/agent-card.json'), $cancellation);
    }

    /**
     * The card of the agent at this address, with proof that it holds the key of the card: it signs a random number
     * of ours together with its address. A card copied from another agent, or fetched from it on our behalf, fails.
     *
     * spec: brief/decisions.md#решения-по-доработкам-2026-11-18 — a neighbour is added only when its card proves the key
     * @return array<array-key, mixed>
     * @throws RuntimeException the card does not prove its key
     */
    public function provenCard(string $base, ?Cancellation $cancellation = null): array {
        $nonce = bin2hex(random_bytes(16));
        $card = $this->request(new Request(rtrim($base, '/') . '/.well-known/agent-card.json?nonce=' . $nonce), $cancellation);
        $key = self::cardKey($card);
        $proof = isset($card['mercurius']) && is_array($card['mercurius']) && isset($card['mercurius']['proof']) && is_string($card['mercurius']['proof'])
            ? $card['mercurius']['proof']
            : '';
        if ($key === null || !AgentIdentity::verify($key, AgentIdentity::cardProofData($nonce, $base), $proof)) {
            throw new RuntimeException(t('peer.a2a_client.card_not_proven'));
        }
        return $card;
    }

    /**
     * @param list<string> $path
     * @param list<array{name: string, bytes: string}> $files
     * @param array{tokens?: int, leaderRun?: int, parentTask?: string} $lead
     * @return array<array-key, mixed> the task
     */
    public function send(PeerEndpoint $peer, #[SensitiveParameter] string $token, string $messageId, string $text, int $depth, array $path, ?Cancellation $cancellation = null, array $files = [], ?string $contextId = null, array $lead = []): array {
        // spec: brief/internet.md#между-агентами — files go ahead by POST /a2a/files (form-data); bytes in the message only by
        // WebSocket when A2A_FILE_TRANSPORT=ws
        $refs = [];
        if ($files !== [] && !($this->fileTransport === 'ws' && self::transport($peer) === 'ws')) {
            $refs = $this->upload($peer, $token, $files, $cancellation);
            $files = [];
        }
        return self::taskOf($this->call($peer, $token, 'SendMessage', self::message($messageId, $text, $depth, $path, $files, $refs, $contextId, $lead), $cancellation));
    }

    /**
     * Asks the neighbour to stop a task it was given.
     *
     * @return array<array-key, mixed> the task
     */
    public function cancel(PeerEndpoint $peer, #[SensitiveParameter] string $token, string $taskId, ?Cancellation $cancellation = null): array {
        return $this->call($peer, $token, 'CancelTask', ['id' => $taskId], $cancellation);
    }

    /** @param array<array-key, mixed> $task the context of a task at the neighbour; '' when it says none */
    public static function contextOf(array $task): string {
        $context = isset($task['contextId']) && is_string($task['contextId']) ? $task['contextId'] : null;
        return is_string($context) && preg_match('~^[\w.:-]{1,100}$~D', $context) === 1 ? $context : '';
    }

    /**
     * Sends files to the neighbour ahead of a message; returns references to them.
     *
     * @param list<array{name: string, bytes: string}> $files
     * @return list<array{id: string, filename: string, mediaType: string}>
     */
    public function upload(PeerEndpoint $peer, #[SensitiveParameter] string $token, array $files, ?Cancellation $cancellation = null): array {
        [$type, $body] = A2a::multipart($files);
        $url = rtrim($peer->peerUrl(), '/') . '/a2a/files';
        [$request, $nonce] = $this->signed($peer, $token, 'POST', $url, $body);
        $request->setHeader('content-type', $type);
        $request->setTransferTimeout(120);
        $data = $this->request($request, $cancellation, $peer->peerPublicKey(), $nonce);
        $refs = [];
        /** @var mixed $file */
        foreach (isset($data['files']) && is_array($data['files']) ? $data['files'] : [] as $file) {
            if (is_array($file) && isset($file['id'], $file['filename'], $file['mediaType']) && is_string($file['id']) && is_string($file['filename']) && is_string($file['mediaType'])) {
                $refs[] = ['id' => $file['id'], 'filename' => $file['filename'], 'mediaType' => $file['mediaType']];
            }
        }
        if (count($refs) !== count($files)) {
            $error = isset($data['error']) && is_string($data['error']) ? $data['error'] : '';
            throw new RuntimeException(t('peer.a2a_client.files_not_taken') . mb_substr($error, 0, 200));
        }
        return $refs;
    }

    /**
     * A file of an answer: GET /a2a/files/<number>, the answer signed by the neighbour's key.
     *
     * @return array{name: string, bytes: string}
     */
    public function download(PeerEndpoint $peer, #[SensitiveParameter] string $token, string $id, string $name, ?Cancellation $cancellation = null): array {
        [$request, $nonce] = $this->signed($peer, $token, 'GET', rtrim($peer->peerUrl(), '/') . '/a2a/files/' . rawurlencode($id), '');
        $request->setTransferTimeout(120);
        $request->setInactivityTimeout(60);
        $request->setBodySizeLimit(A2a::FILE_MAX + 1);
        try {
            $response = $this->http->request($request, $cancellation ?? new \Amp\NullCancellation());
            $bytes = $response->getBody()->buffer($cancellation, A2a::FILE_MAX + 1);
        } catch (Throwable $e) {
            throw new RuntimeException(t('peer.a2a_client.sosed_ne_otvetil') . (new \ReflectionClass($e))->getShortName() . ').');
        }
        if ($response->getStatus() !== 200 || !AgentIdentity::verify($peer->peerPublicKey(), AgentIdentity::responseData($nonce, $bytes), $response->getHeader('x-a2a-signature') ?? '')) {
            throw new RuntimeException(t('peer.a2a_client.file_not_given'));
        }
        return ['name' => $name, 'bytes' => $bytes];
    }

    /**
     * The files an answer refers to.
     *
     * @param array<array-key, mixed> $task
     * @return list<array{id: string, raw: string, name: string}> a reference (id) or bytes in base64 (raw)
     */
    public static function answerFiles(array $task): array {
        $message = isset($task['status']) && is_array($task['status']) && isset($task['status']['message']) && is_array($task['status']['message']) ? $task['status']['message'] : [];
        $files = [];
        /** @var mixed $part */
        foreach (isset($message['parts']) && is_array($message['parts']) ? $message['parts'] : [] as $part) {
            if (!is_array($part) || count($files) >= A2a::COUNT_MAX) {
                continue;
            }
            /** @var mixed $named */
            $named = $part['filename'] ?? null;
            $name = A2a::fileName(is_string($named) ? $named : 'file');
            /** @var mixed $url */
            $url = $part['url'] ?? null;
            /** @var mixed $raw */
            $raw = $part['raw'] ?? null;
            if (is_string($url) && str_starts_with($url, A2a::SCHEME)) {
                $files[] = ['id' => substr($url, strlen(A2a::SCHEME)), 'raw' => '', 'name' => $name];
            } elseif (is_string($raw)) {
                $files[] = ['id' => '', 'raw' => $raw, 'name' => $name];
            }
        }
        return $files;
    }

    /**
     * A request signed by the key chosen for the neighbour: the entrance token, the key, a time and a one-time number.
     *
     * @param non-empty-string $method
     * @return array{Request, string} the request and its number
     */
    private function signed(PeerEndpoint $peer, #[SensitiveParameter] string $token, string $method, string $url, string $body): array {
        $identity = $this->identityFor($peer);
        $timestamp = (string) time();
        $nonce = bin2hex(random_bytes(16));
        $path = parse_url($url, PHP_URL_PATH);
        $request = new Request($url, $method, $body);
        $request->setHeader('authorization', 'Bearer ' . $token);
        $request->setHeader('a2a-version', '1.0');
        $request->setHeader('x-a2a-key', base64_encode($identity->publicKey));
        $request->setHeader('x-a2a-timestamp', $timestamp);
        $request->setHeader('x-a2a-nonce', $nonce);
        foreach ($this->about() as $claim => $value) {
            $request->setHeader('x-a2a-' . $claim, $value);
        }
        $request->setHeader('x-a2a-signature', $identity->sign(AgentIdentity::requestData($method, is_string($path) ? $path : '/', $timestamp, $nonce, $body, $peer->peerUrl())));
        return [$request, $nonce];
    }

    /**
     * The parameters of SendMessage: the text and the files as parts of A2A v1 (raw bytes in base64, a file name).
     *
     * spec: brief/channels.md#личные-сообщения-участникам — not only text: files to other agents
     *
     * @param list<string> $path
     * @param list<array{name: string, bytes: string}> $files bytes in the message (WebSocket)
     * @param list<array{id: string, filename: string, mediaType: string}> $refs files sent ahead
     * @param array{tokens?: int, leaderRun?: int, parentTask?: string} $lead the token cap of the task, the leader's run
     *        and the task its run works on: the neighbour takes the smaller budget and keeps the rest for its trace
     * @return array<string, mixed>
     */
    public static function message(string $messageId, string $text, int $depth, array $path, array $files = [], array $refs = [], ?string $contextId = null, array $lead = []): array {
        $parts = $text === '' ? [] : [['text' => $text, 'mediaType' => 'text/plain']];
        foreach ($files as $file) {
            $parts[] = ['raw' => base64_encode($file['bytes']), 'filename' => $file['name'], 'mediaType' => A2a::mediaType('', $file['name'])];
        }
        foreach ($refs as $ref) {
            $parts[] = ['url' => A2a::SCHEME . $ref['id'], 'filename' => $ref['filename'], 'mediaType' => $ref['mediaType']];
        }
        $message = ['role' => 'ROLE_USER', 'messageId' => $messageId, 'parts' => $parts];
        if ($contextId !== null && $contextId !== '') {
            // spec: brief/network.md#сеть-агентов-1 — an answer to a question of the neighbour goes into the same context
            $message['contextId'] = $contextId;
        }
        return [
            'message' => $message,
            'metadata' => ['mercurius' => ['depth' => $depth, 'path' => $path] + $lead],
        ];
    }

    /**
     * @param array<array-key, mixed> $result
     * @return array<array-key, mixed>
     */
    public static function taskOf(array $result): array {
        return isset($result['task']) && is_array($result['task']) ? $result['task'] : $result;
    }

    /** @return array<array-key, mixed> the task */
    public function get(PeerEndpoint $peer, #[SensitiveParameter] string $token, string $taskId, ?Cancellation $cancellation = null): array {
        return $this->call($peer, $token, 'GetTask', ['id' => $taskId], $cancellation);
    }

    /**
     * The public key a card announces; null when it has none.
     *
     * @param array<array-key, mixed> $card
     */
    public static function cardKey(array $card): ?string {
        $key = isset($card['mercurius']) && is_array($card['mercurius']) && isset($card['mercurius']['publicKey']) && is_string($card['mercurius']['publicKey']) ? $card['mercurius']['publicKey'] : null;
        return $key === null || AgentIdentity::fingerprintOf($key) === null ? null : $key;
    }

    /**
     * The number a neighbour gave its task, when it is a plain number of letters, digits and - _ . : (up to 100), not a
     * path; null otherwise. The number is the neighbour's word: it is only shown and asked back, never made a path.
     *
     * spec: brief/decisions.md#решения-по-доработкам-2026-11-18 — files of an answer stay in the inbox of their task
     * @param array<array-key, mixed> $task
     */
    public static function taskId(array $task): ?string {
        if (!isset($task['id']) || !is_string($task['id'])) {
            return null;
        }
        $id = $task['id'];
        return preg_match('~^[\w.:-]{1,100}$~D', $id) === 1 && !str_contains($id, '..') ? $id : null;
    }

    /** @param array<array-key, mixed> $task */
    public static function state(array $task): string {
        return isset($task['status']) && is_array($task['status']) && isset($task['status']['state']) && is_string($task['status']['state']) ? $task['status']['state'] : '';
    }

    /** @param array<array-key, mixed> $task */
    public static function answer(array $task): string {
        $message = isset($task['status']) && is_array($task['status']) && isset($task['status']['message']) && is_array($task['status']['message']) ? $task['status']['message'] : [];
        return A2a::text($message);
    }

    /**
     * @param array<string, mixed> $params
     * @return array<array-key, mixed>
     */
    private function call(PeerEndpoint $peer, #[SensitiveParameter] string $token, string $method, array $params, ?Cancellation $cancellation): array {
        if (self::transport($peer) === 'ws' && $this->connect !== null) {
            return $this->socket($peer, $token)->request($method, $params, $cancellation);
        }
        $identity = $this->identityFor($peer);
        $url = rtrim($peer->peerUrl(), '/') . '/a2a';
        $body = json_encode(['jsonrpc' => '2.0', 'id' => bin2hex(random_bytes(4)), 'method' => $method, 'params' => $params], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
        $timestamp = (string) time();
        $nonce = bin2hex(random_bytes(16));
        $path = parse_url($url, PHP_URL_PATH);
        $request = new Request($url, 'POST', $body);
        $request->setHeader('authorization', 'Bearer ' . $token);
        $request->setHeader('content-type', 'application/json');
        $request->setHeader('a2a-version', '1.0');
        $request->setHeader('x-a2a-key', base64_encode($identity->publicKey));
        $request->setHeader('x-a2a-timestamp', $timestamp);
        $request->setHeader('x-a2a-nonce', $nonce);
        foreach ($this->about() as $claim => $value) {
            $request->setHeader('x-a2a-' . $claim, $value);
        }
        $request->setHeader('x-a2a-signature', $identity->sign(AgentIdentity::requestData('POST', is_string($path) ? $path : '/a2a', $timestamp, $nonce, $body, $peer->peerUrl())));
        $data = $this->request($request, $cancellation, $peer->peerPublicKey(), $nonce);
        if (isset($data['error']) && is_array($data['error'])) {
            $message = isset($data['error']['message']) && is_string($data['error']['message']) ? $data['error']['message'] : 'error';
            throw new RuntimeException(t('peer.a2a_client.sosed_otkazal') . mb_substr($message, 0, 200));
        }
        return isset($data['result']) && is_array($data['result']) ? $data['result'] : throw new RuntimeException(t('peer.a2a_client.sosed_otvetil_bez_rezultata'));
    }

    /** The open connection to the neighbour under the key chosen for it; a new one when the old one closed. */
    private function socket(PeerEndpoint $peer, #[SensitiveParameter] string $token): A2aSocket {
        $identity = $this->identityFor($peer);
        $peerFingerprint = AgentIdentity::fingerprintOf($peer->peerPublicKey()) ?? '';
        // spec: brief/network.md#подключения-агентов-решение-владельца-2026-11-17 — any live connection with the neighbour serves,
        // whichever side opened it
        $live = $this->links?->to($peerFingerprint);
        if ($live !== null) {
            return $live;
        }
        $slot = $peer->peerName() . "\0" . $identity->fingerprint();
        $open = $this->sockets[$slot] ?? null;
        if ($open !== null && $open->alive()) {
            return $open;
        }
        $url = self::socketUrl($peer);
        try {
            $channel = ($this->connect ?? throw new RuntimeException('no websocket'))($url, $token);
        } catch (RuntimeException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new RuntimeException(t('peer.a2a_client.sosed_ne_otvetil') . (new \ReflectionClass($e))->getShortName() . ').');
        }
        $socket = A2aSocket::open($channel, $identity, $peer->peerPublicKey(), 10.0, $this->serveFor === null ? null : ($this->serveFor)($peerFingerprint, $peer->peerName(), $peer->peerUrl()), $this->about(), $url);
        $this->links?->add(A2aLinks::OUT, $peer->peerName(), $peerFingerprint, $socket);
        return $this->sockets[$slot] = $socket;
    }

    /** @return array<array-key, mixed> */
    private function request(Request $request, ?Cancellation $cancellation, ?string $peerKey = null, string $nonce = ''): array {
        $request->setTransferTimeout(30);
        $request->setInactivityTimeout(30);
        try {
            $response = $this->http->request($request, $cancellation ?? new \Amp\NullCancellation());
            $body = $response->getBody()->buffer($cancellation, 1_048_576);
        } catch (Throwable $e) {
            throw new RuntimeException(t('peer.a2a_client.sosed_ne_otvetil') . (new \ReflectionClass($e))->getShortName() . ').');
        }
        if ($response->getStatus() === 404 && $peerKey !== null) {
            throw new A2aMoved(t('peer.a2a_client.moved'));
        }
        if ($peerKey !== null && !in_array($response->getStatus(), [401, 403], true)
            && !AgentIdentity::verify($peerKey, AgentIdentity::responseData($nonce, $body), $response->getHeader('x-a2a-signature') ?? '')) {
            throw new RuntimeException(t('peer.a2a_client.otvet_podpisan_ne_klyuchom_etogo'));
        }
        try {
            /** @var mixed $data */
            $data = json_decode($body, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new RuntimeException(sprintf(t('peer.a2a_client.sosed_otvetil_ne_json_http'), $response->getStatus()));
        }
        if (!is_array($data)) {
            throw new RuntimeException(t('peer.a2a_client.sosed_otvetil_ne_obektom'));
        }
        if ($response->getStatus() === 401 || $response->getStatus() === 403) {
            $message = isset($data['error']) && is_array($data['error']) && isset($data['error']['message']) && is_string($data['error']['message']) ? $data['error']['message'] : '';
            throw new RuntimeException(t('peer.a2a_client.sosed_ne_pustil') . mb_substr($message, 0, 200));
        }
        return $data;
    }
}
