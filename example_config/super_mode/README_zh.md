# Etherguard
[English](README.md) | [中文](#)

## Super Mode（HTTP-only Control API v2）

此模式是受到[n2n](https://github.com/ntop/n2n)的啟發，分為SuperNode和EdgeNode兩種節點。
SuperNode運行一個純HTTP控制服務。EdgeNode透過HTTP註冊，取得peer快照，並交換延遲量測資料。SuperNode執行[Floyd-Warshall演算法](https://zh.wikipedia.org/wiki/zh-tw/Floyd-Warshall算法)，並把計算結果分發給所有EdgeNode。

**重大變更：** Super模式不再使用UDP listener、WireGuard私鑰、UAPI或`wg`命令。如果你有舊版v1設定檔包含`PrivKeyV4`、`PrivKeyV6`、`ListenPort`、`FwMark`、`API_Prefix`、`ListenPort_EdgeAPI`或`ListenPort_ManageAPI`，會收到`legacy_udp_field`錯誤。升級前必須遷移到v2 `SuperConfigV2` YAML。

## 快速上手

### 1. 生成設定檔

按照需求修改`gensuper.yaml`，然後生成所有設定檔：

```bash
./etherguard-go -mode gencfg -cfgmode super -config example_config/super_mode/gensuper.yaml
```

產生器會建立v2 Super YAML和每個Edge的YAML，每個Edge都有獨立的ControlPSKey。每個Edge的HMAC簽名金鑰只出現在該Edge的設定檔和Super對應的peer entry中。

### 2. 啟動SuperNode

```bash
./etherguard-go -config example_config/super_mode/EgNet_super.yaml -mode super
```

SuperNode監聽兩個TCP埠（Edge API和Management API）。不會建立UDP socket。如果傳入舊版v1設定檔，程式會立即退出：

```
control v2: legacy_udp_field: "PrivKeyV4" is no longer accepted in -mode super; use a v2 SuperConfigV2 YAML
```

### 3. 啟動EdgeNode

```bash
./etherguard-go -config example_config/super_mode/EgNet_edge001.yaml -mode edge
./etherguard-go -config example_config/super_mode/EgNet_edge002.yaml -mode edge
```

### 4. 試試看

範例設定使用`stdio`模式。在其中一個Edge視窗中鍵入：

```
b1aaaaaaaaaa
```

`b`是廣播位址（`FF:FF:FF:FF:FF:FF`），`1`是MAC位址（`AA:BB:CC:DD:EE:01`），`aaaaaaaaaa`是後面的payload。你應該能在另一個視窗上看見同樣的字串。

## 架構

### 運作方式

1. 每個Edge向SuperNode發送帶簽名的`POST /edge/v2/register`，宣告自己的本地候選位址和STUN候選位址。
2. SuperNode將Edge記錄在控制狀態中，回傳`ControlV2Snapshot`，包含所有已知peer和當前參數。
3. Edge定期發送`POST /edge/v2/report`，攜帶延遲觀測值（pong結果）和刷新的候選位址。
4. SuperNode將延遲資料餵入Floyd-Warshall圖，重新計算NextHopTable。
5. Edge訂閱`GET /edge/v2/events`（SSE串流）或輪詢`GET /edge/v2/snapshot`來偵測變化。
6. 當snapshot revision改變時，Edge將新的peer list和路由表套用到WireGuard裝置上。

### Control API v2 路由

所有路由在Super YAML設定的`APIPrefix`下提供服務（預設`/edge/v2`）。

| Method | Path | 用途 |
|--------|------|------|
| POST | `/edge/v2/register` | Edge自我介紹；回傳初始snapshot |
| POST | `/edge/v2/report` | Edge發送pong、候選位址刷新、心跳 |
| GET | `/edge/v2/snapshot` | Edge取得當前peer快照（ETag/304） |
| GET | `/edge/v2/events` | SSE串流，推送狀態變更事件 |

### HMAC請求簽名

每個Control API v2請求攜帶四個header：

| Header | 值 |
|--------|-----|
| `X-EG-NodeID` | 十進位NodeID |
| `X-EG-Timestamp` | Unix秒數 |
| `X-EG-Nonce` | 每次請求唯一的token |
| `X-EG-Signature` | `hex(HMAC-SHA256(key=ControlPSKey, msg=canonical))` |

標準簽名字串為：
```
METHOD\nescaped-path\nunix-timestamp\nnonce\nhex(SHA-256(body))
```

Super會驗證所有四個header。超過60秒時鐘偏差、nonce重放、body過大（>1 MiB）或簽名不正確的請求，都會收到統一的`"control auth failed"`回應，不會透露哪個檢查失敗或包含任何金鑰資訊。

**安全邊界：** ControlPSKey是每個Edge的密鑰。它絕對不能出現在URL、log檔、snapshot或任何給其他Edge的HTTP回應中。`SuperNodeV2Ref.ControlPSKey`和`SuperConfigV2Peer.ControlPSKey`上的`json:"-"`標籤防止序列化洩漏。

### 透過反向代理提供TLS

HMAC簽名進行身份驗證但不加密。在生產環境中，你**必須**在SuperNode前面部署反向代理（nginx、Caddy等）來提供TLS。SuperNode本身只提供HTTP服務。

```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/etherguard.crt;
    ssl_certificate_key /etc/ssl/etherguard.key;

    location /edge/v2/ {
        proxy_pass http://127.0.0.1:3456/edge/v2/;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
    }
    location /edge/v2/manage/ {
        proxy_pass http://127.0.0.1:3456/edge/v2/manage/;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### SSE與輪詢回退

Edge連接`GET /edge/v2/events`取得即時狀態變更通知。串流使用標準Server-Sent Events格式：

- `id:` 欄位單調遞增（`evt-N`）。
- `event:` 類型為`peer_change`、`peer_gone`、`params_change`或`revision`。
- `data:` 攜帶JSON payload（例如`{\"node_id\":1,\"node_name\":\"Node001\"}`）。

重新連線時，Edge發送`Last-Event-ID`從保留的buffer繼續接收。如果伺服器無法回放（ID早於保留範圍），Edge必須重新取得完整的snapshot。

輪詢僅作為回退機制：`ControlHTTPClient.Sync`首先建立SSE串流，僅在串流連線或解析失敗後才啟動定時snapshot輪詢，並在串流恢復健康時立即取消輪詢。當Super的event hub關閉時，進行中的SSE串流會終止，使Edge偵測到失敗並回退到輪詢。Edge使用ETag/304條件請求來避免傳輸未變更的snapshot。

### STUN候選位址探索

Super透過參數串流中的`STUNServers`欄位將STUN伺服器分配給所有Edge。每個Edge使用現有的WireGuard bind socket（與UDP資料路徑相同的port）執行STUN binding請求。XOR-MAPPED位址成為`stun`候選位址。

**同socket限制：** STUN候選位址是從WireGuard bind socket量測的。如果STUN伺服器看到的source port與WireGuard socket不同，該候選位址無效，因為NAT mapping是基於port的。Edge不會為STUN建立第二個UDP socket。

接受`stun:host:port`和`stun://host:port`兩種URI格式。主機可以是IP literal（例如`stun://192.168.1.10:3478`）或語法上合法的DNS主機名（例如`stun://local-stun.example:3478`）。驗證不執行DNS I/O，僅檢查URI格式。DNS解析在`SuperSTUNManager`內部於運行時進行，受設定的per-server超時限制，在IP-only bind parser之前完成。通用endpoint解析（`conn/conn.go`）僅接受IP literal；DNS主機名僅用於STUN，不適用於peer endpoint。STUN刷新在註冊時一次性執行（無週期性刷新）。

### 無relay/TURN

與n2n不同，SuperNode不會轉發任何封包。如果兩個Edge之間的UDP打洞失敗且沒有其他可用路徑，這些Edge無法通訊。沒有回退轉發。

如果需要在打洞失敗的Edge之間提供連通性，請部署relay node：一個在公網上的普通Edge，設定`interface=dummy`。

## SuperNode設定參數（v2）

| Key | 說明 |
|-----|------|
| NodeName | 節點名稱（最多32字元） |
| APIUrl | Edge API listener的URL（例如`http://host:3456`） |
| APIPrefix | API路徑前綴（例如`/edge/v2`） |
| ManagementAuth | `{User, PasswordHash}`，用於`/manage/*`端點 |
| STUNServers | STUN伺服器URI列表（`stun:host:port`或`stun://host:port`）；主機可以是IP literal或DNS主機名 |
| STUNRequestTimeoutSeconds | 每次STUN請求的超時時間 |
| STUNRefreshIntervalSeconds | 保留：存在於設定結構中但目前無效；STUN在註冊時一次性執行（無週期性刷新） |
| PollIntervalSeconds | Edge輪詢snapshot的間隔 |
| ReportIntervalSeconds | Edge回報（pong/候選位址）的間隔 |
| HeartbeatIntervalSeconds | Edge心跳間隔 |
| EventReplay | SSE回放ring depth（預設256） |
| PeerAliveTimeoutSeconds | 節點無反應多久後被移除（秒） |
| UsePSKForInterEdge | 是否為Edge之間的WireGuard流量產生成對PSK |
| DampingFilterRadius | 延遲平滑的低通濾波器window半徑 |
| Peers | 預授權的Edge peer列表 |

### Peers（Super端）

| Key | 說明 |
|-----|------|
| NodeID | Edge的節點ID |
| NodeName | Edge的名稱 |
| ControlPSKey | 該Edge的HMAC簽名密鑰（不會暴露給其他Edge） |
| AdditionalCost | 額外轉發成本（毫秒），`-1`代表使用Edge自己的設定 |

## EdgeNode設定參數（v2）

### EdgeConfig Root

Edge v2設定用`SuperNodeV2`參照取代舊版`DynamicRoute.SuperNode`區塊。包含`LegacySuper`金鑰或`DynamicRoute.SuperNode`金鑰（包括`UseSuperNode: false`）的v1 Edge設定會收到類型化的`legacy_udp_field`錯誤；它不會靜默地變為static模式。

### SuperNodeV2

| Key | 說明 |
|-----|------|
| APIUrl | SuperNode的Edge API URL |
| APIPrefix | API路徑前綴（必須與Super的`APIPrefix`一致） |
| NodeID | SuperNode的非特殊NodeID |
| ControlPSKey | 此Edge的HMAC簽名密鑰（必須與Super的peer entry一致） |

### Interface、LogLevel、Peers

與[Static Mode](../static_mode/README_zh.md)設定相同。在Super模式下，`Peers`列表通常為空，因為peer資訊從SuperNode下載。

## v1設定檔遷移

如果使用舊版v1設定執行`-mode super`，會看到：

```
Error: control v2: legacy_udp_field: "PrivKeyV4" is no longer accepted in -mode super
```

被拒絕的欄位：`PrivKeyV4`、`PrivKeyV6`、`ListenPort`、`FwMark`、`API_Prefix`、`ListenPort_EdgeAPI`、`ListenPort_ManageAPI`。

遷移步驟：
1. 產生新的v2設定：`./etherguard-go -mode gencfg -cfgmode super -config gensuper.yaml`
2. 檢查產生的`EgNet_super.yaml`和edge YAML。
3. 使用`-mode super -config EgNet_super.yaml`啟動。

## VPP狀態

VPP整合在此版本中被排除且未驗證。沒有配備libmemif的主機執行過`make vpp`。遷移涉及`device/`、`main_edge.go`和`main_super.go`，因此VPP建構或運行時回歸是可能的。在任何發布前，請在有libmemif的主機上驗證`make vpp`。

## HTTP Manage API

舊版`/manage/*`端點保留給前端工具使用：

```bash
curl "http://127.0.0.1:3456/edge/v2/manage/super/state?Password=passwd_hash_example"
```

完整的端點列表（peer/add、peer/del、peer/update、super/update、super/state）請參閱[舊版Manage API文件](#http-manage-api)。

## 範例設定檔

| 檔案 | 說明 |
|------|------|
| `gensuper.yaml` | 用於產生v2設定的輸入檔 |
| `EgNet_super.yaml` | 產生的SuperNode v2設定 |
| `EgNet_edge001.yaml` | 產生的EdgeNode 1 v2設定 |
| `EgNet_edge002.yaml` | 產生的EdgeNode 2 v2設定 |
| `EgNet_edge100.yaml` | 產生的EdgeNode 100 v2設定 |

## 下一步：[P2P Mode](../p2p_mode/README_zh.md)
