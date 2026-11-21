# mercurius-peer

[English](README.md) | [Русский](README.ru.md) | **中文**

> 本文由模型翻译，尚未经人工审校；如有出入，以英文版为准。

AMPHP 智能体的智能体间通信部分，A2A v1.0：智能体由其 ECDSA P-256 密钥标识，而非共享令牌。客户端获取邻居的卡片并检查该卡片能证明其密钥，发送任务并查询其状态或取消——通过一条握手时验证双方密钥的 WebSocket，或通过每个请求都签名的 HTTP——并在消息之前发送文件。

属于 [Mercurius](https://github.com/opencck/mercurius)——一个自主的个人智能体。该软件包不依赖 Mercurius 应用，可以单独使用。

**状态：** 已被 Mercurius 在其各实例之间使用。服务端部分（谁可以进入、应答邻居的运行、文件存储）位于应用中：它依赖应用的参与者、策略和智能体循环。

**技术栈：** PHP 8.2+、AMPHP v3、`amphp/http-client` v5、OpenSSL。

## 组成部分

| 类 | 作用 |
|----|------|
| `AgentIdentity` | P-256 密钥：生成、从 PEM 读取、签名、验证、指纹；每个签名所覆盖的确切数据 |
| `A2aClient` | 卡片（附其密钥证明）、`SendMessage`、`GetTask`、`CancelTask`、消息之前的文件；按卡片选择 WebSocket 或签名 HTTP |
| `A2aSocket`、`A2aChannel` | 双方密钥握手之后，在任意通道上的一条 JSON-RPC 连接；双向的请求和通知 |
| `A2aLinks` | 与其他智能体之间的在线连接，双向均包含 |
| `A2a` | 错误码、文件限制和方案、消息文本、multipart 上传 |
| `PeerEndpoint`、`IdentityKeys` | 应用需提供的内容：它对邻居的记录；它向选定邻居出示的密钥 |

## 使用

```php
use Mercurius\Peer\A2aClient;
use Mercurius\Peer\AgentIdentity;

$me = AgentIdentity::fromPem($pemKeptByYou);
$client = new A2aClient($httpClient, $me);
$card = $client->provenCard('https://neighbour.example.com');   // throws when the card does not prove its key
$task = $client->send($neighbour, $token, bin2hex(random_bytes(8)), 'Summarise the report', 0, []);
```

错误文本为英文；可一次性提供你自己的：`Mercurius\Peer\Texts::translateWith(fn(string $key): string => ...)`。

## 检查

`composer check` —— PHPUnit、PHPStan（level max）和 Psalm（level 1）。Mercurius 会将客户端和服务端一起检查。

## 许可证

[MIT](LICENSE)
