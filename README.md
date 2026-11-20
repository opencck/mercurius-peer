# mercurius-peer

**English** | [Русский](README.ru.md)

The agent-to-agent side of an AMPHP agent, A2A v1.0: an agent is known by its ECDSA P-256 key, not by a shared
token. The client fetches a neighbour's card and checks that the card proves its key, sends a task and asks for its
state or cancels it — over one WebSocket whose handshake proves both keys, or by HTTP with every request signed — and
sends files ahead of a message.

Part of [Mercurius](https://github.com/opencck/mercurius) — an autonomous personal agent. The package does not depend on the Mercurius application and can be used on its own.

**Status:** used by Mercurius between its instances. The server side (who may come in, the runs that answer a
neighbour, the store of files) lives in the application: it depends on its participants, policies and agent loop.

**Stack:** PHP 8.2+, AMPHP v3, `amphp/http-client` v5, OpenSSL.

## Parts

| Class | What it does |
|-------|--------------|
| `AgentIdentity` | A P-256 key: make, read from PEM, sign, verify, fingerprint; the exact data each signature covers |
| `A2aClient` | Card (with proof of its key), `SendMessage`, `GetTask`, `CancelTask`, files ahead of a message; WebSocket or signed HTTP, by the card |
| `A2aSocket`, `A2aChannel` | One JSON-RPC connection over any channel after a handshake of both keys; requests both ways and notices |
| `A2aLinks` | The live connections with other agents, in both directions |
| `A2a` | Error codes, file limits and scheme, the text of a message, a multipart upload |
| `PeerEndpoint`, `IdentityKeys` | What an application gives: its record of a neighbour; the keys it presents to chosen neighbours |

## Use

```php
use Mercurius\Peer\A2aClient;
use Mercurius\Peer\AgentIdentity;

$me = AgentIdentity::fromPem($pemKeptByYou);
$client = new A2aClient($httpClient, $me);
$card = $client->provenCard('https://neighbour.example.com');   // throws when the card does not prove its key
$task = $client->send($neighbour, $token, bin2hex(random_bytes(8)), 'Summarise the report', 0, []);
```

Texts of errors are English; give your own once: `Mercurius\Peer\Texts::translateWith(fn(string $key): string => ...)`.

## Checks

`composer check` — PHPUnit, PHPStan (level max) and Psalm (level 1). Mercurius checks client and server together.

## License

[MIT](LICENSE)
