# mercurius-peer

**English** | [Русский](README.ru.md)

A protocol for connecting Mercurius instances over WebSocket: agent card, task, status stream, result, cancellation and reconnection — client and server. One instance can use others as its agents and sub-agents.

Part of [Mercurius](https://github.com/opencck/mercurius) — an autonomous personal agent. The package does not depend on the Mercurius application and can be used on its own.

**Status:** the code still lives in the main repository, in [`src/App/Peer/`](https://github.com/opencck/mercurius/tree/master/src/App/Peer) (A2A over WebSocket and HTTP, keys of agents, delegation with a deadline and cancelling), and moves here next.

**Stack:** PHP 8.2+, AMPHP v3.

## License

[MIT](LICENSE)
