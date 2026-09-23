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
| GET | `/edge/v2/cluster/link` | HTTP Upgrade，僅 Super 對 Super；HMAC(`Cluster.Secret`) |

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

    location /edge/v2/cluster/link {
        proxy_pass http://127.0.0.1:3456/edge/v2/cluster/link;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_read_timeout 90s;
        proxy_send_timeout 90s;
    }
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

**多WAN Edge：** 在Linux上，擁有多個上行鏈路（例如多條default route）的Edge會經由每一個上行鏈路各發送一次STUN探測，仍然使用同一個WireGuard socket。每個探測都會固定該鏈路的來源位址與出口介面，因此同時支援各介面的default route以及`ip rule from <src>`策略路由。Edge會為每個不同的公網`ip:port`回報一個`stun`候選位址，並附上經由核心預設路由看到的mapping。每個介面每種位址族只探測一個位址，最多8個上行鏈路，且只計入已啟用並有載波的介面。使用`--bindmode std`或非Linux平台時，只會探索預設路由的mapping。

接受`stun:host:port`和`stun://host:port`兩種URI格式。主機可以是IP literal（例如`stun://192.168.1.10:3478`）或語法上合法的DNS主機名（例如`stun://local-stun.example:3478`）。驗證不執行DNS I/O，僅檢查URI格式。DNS解析在`SuperSTUNManager`內部於運行時進行，受設定的per-server超時限制，在IP-only bind parser之前完成。通用endpoint解析（`conn/conn.go`）僅接受IP literal；DNS主機名僅用於STUN，不適用於peer endpoint。`STUNRefreshIntervalSeconds`會主動排程週期性探索：每次刷新保留local候選位址、移除過期的STUN-only候選位址，並去除重複結果。STUN探索不是keepalive。

### 直接連線與觀察到的回退位址

省略Edge的`DirectConnectivity`區塊時，Super peer的動態預設值如下：

| Key | 預設秒數 | 用途 |
|-----|---------:|------|
| PersistentKeepaliveSeconds | 25 | 為Super下載的peer維持NAT mapping |
| SendPingIntervalSeconds | 16 | 直接peer ping頻率 |
| PeerAliveTimeoutSeconds | 70 | Edge本地動態peer存活超時 |
| TimeoutCheckIntervalSeconds | 10 | 離線檢查頻率 |
| ConnNextTrySeconds | 5 | 下一個候選位址嘗試前的延遲 |

這些設定只套用到Super下載的peer；static peer策略不變，也不會讓STUN成為keepalive。

#### 最低延遲endpoint選擇

peer存活後，Edge會持續量測通往它的每一條路徑：每個（本地上行鏈路, 遠端候選位址）組合每輪發送一個加密探測，當某條路徑連續數輪明顯更快時，peer就會切換到該路徑。雙方各自只評估自己的出站路徑，兩個方向可以使用不同的上行鏈路。探測同時維持備用上行鏈路的NAT mapping，因此探測間隔應低於NAT的UDP超時（約25秒以內較安全）。只有單一路徑的peer不會產生額外開銷。探測結果不會影響路由延遲。

除了發布的候選位址，Edge也會探測peer-reflexive位址：來自該peer、經過驗證但未被漫遊保護採用的封包來源位址。在endpoint-dependent mapping的NAT之後，peer看到的port與STUN回報的port不同，因此這些位址是抵達該上行鏈路的唯一途徑。每個peer最多保留四個，並在Edge本地peer存活超時後過期。

| Key | 預設值 | 用途 |
|-----|-------:|------|
| DisableEndpointSelection | false | 關閉最低延遲選擇 |
| EndpointProbeIntervalSeconds | ping間隔 | 探測輪次之間的秒數 |
| EndpointSwitchMarginMS | 5 | 切換前RTT至少需改善的毫秒數 |
| EndpointSwitchMarginPercent | 15 | 切換前RTT至少需改善的百分比（相對目前RTT），取兩者中較大的門檻 |
| EndpointSwitchRounds | 3 | 較快路徑需連續勝出的輪數 |

每個Edge在每次report最多可回報256個觀察目標endpoint。Super只發布匿名聚合的回退位址：每個目標最多16個hint，其中IPv4與IPv6各最多14個。snapshot絕不包含reporter身分或時間戳記。投票依Super端的`PeerAliveTimeoutSeconds`到期。

嘗試連線到尚未存活的peer時，候選位址類別的順序固定為local < STUN < observed。reporter count只在observed候選位址內排序；它不會使observed候選位址超過local或STUN。peer存活後，最低延遲選擇可能會把它移到任何量測更快的候選位址。

## Super獨佔的listen port策略

`ListenPortPriority`是**僅屬於Super**的有序候選清單，是Edge應該優先綁定哪個UDP listen port的唯一真實來源。Super在`ControlV2Parameters`中發布這個清單；每個對該Super註冊的Edge，都會在snapshot中看到同一份有序集合。

### 啟動時必須經過bootstrap

Edge**必須**在綁定任何UDP socket之前，從Super的受保護端點取得策略。`POST /edge/v2/register`回傳的第一份snapshot攜帶當前`ControlV2Parameters`的`ListenPortPriority`欄位；Edge依宣告順序走訪清單，綁定第一個空閒的port。當Edge收到更新的參數串流（`event: params_change`）時，它會切換到新的候選集合重新綁定，不會遺失已註冊狀態。

如果Edge在啟動時無法連到Super（網路斷線、憑證錯誤等），它**不應該**從過期的本機策略綁定port——因為它根本沒有本機策略。Edge會以設定的`PollIntervalSeconds`週期重試`register`，直到收到snapshot。

### 有序候選語義

條目依照它們在YAML中出現的順序走訪：

- `Port:`條目是單一字面port。
- `Range:`條目是左閉右閉的`[From, To]`範圍，依序走訪。
- 後面重複已佔用port的條目會被靜默丟棄（先到者優先，依整數值去重）。
- 展開上限是256個唯一port；任何會把候選集合推過256的條目，會在YAML解析時以類型化的`invalid_candidate`錯誤失敗，而不是靜默截斷。

驗證會拒絕：[1, 65535]以外的port、反轉範圍（`From > To`）、同時設定`Port:`和`Range:`的條目、空條目，以及任何唯一展開超過256的策略。這些都會以`SuperConfigV2.Validate()`錯誤呈現，因此格式錯誤的Super YAML會在啟動時快速失敗。

### Port-zero回退

如果`ListenPortPriority`中的所有候選在主機上都已被佔用（或被OS／防火牆拒絕），Edge會回退到`listen_port = 0`（kernel指派的臨時port）並繼續運行。選擇到的臨時port會在下一次`POST /edge/v2/report`中回報給Super，讓peer即使在策略耗盡時也能知道實際綁定。

回退**僅作為最後手段**：Edge不會為了更快達到port zero而跳過宣告順序中的候選，也不會在完全失敗時中止。回退會以WARN等級記錄，讓操作者能區分「策略耗盡」的Edge和正常Edge。

### Edge / client profile不應攜帶什麼

`ListenPortPriority`是純粹的Super端YAML鍵。本repo中的100個Edge profile（`logs.yaml`和`ngsdn_edge002.yaml`…`ngsdn_edge100.yaml`）**不應**攜帶：

- `ListenPortPriority`（有序候選清單）
- `ListenPort`（v1的裸port欄位）
- `BootstrapListenPortPriority`或任何類似的本機port策略鍵

Edge透過每次`register`／`snapshot`抓取，從Super繼承策略。在Edge profile中硬編碼本機port會靜默覆蓋Super的權威策略，破壞啟動時必須bootstrap的合約。`docs_contract_test.go`中的corpus稽核會列舉每個Edge檔案，只要任何上述鍵重新出現就會失敗。

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
| STUNRefreshIntervalSeconds | 主動進行週期性STUN候選位址探索的間隔；這不是keepalive |
| PollIntervalSeconds | Edge輪詢snapshot的間隔 |
| ReportIntervalSeconds | Edge回報（pong/候選位址）的間隔 |
| HeartbeatIntervalSeconds | Edge心跳間隔 |
| EventReplay | SSE回放ring depth（預設256） |
| PeerAliveTimeoutSeconds | 節點無反應多久後被移除（秒） |
| UsePSKForInterEdge | 是否為Edge之間的WireGuard流量產生成對PSK |
| DampingFilterRadius | 延遲平滑的低通濾波器window半徑 |
| ListenPortPriority | 僅屬於Super的有序UDP listen-port候選清單（參見[Super獨佔的listen port策略](#super獨佔的listen-port策略)）；Edge不應攜帶本機複本 |
| Peers | 預授權的Edge peer列表 |
| Cluster | 可選的 active-active Super 叢集（參見[多 Super 控制平面（active-active）](#多-super-控制平面active-active)）；單 Super 請省略 |

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
| APIUrls | 有序的 Super API URL 清單，用於 sticky failover。設定 `Cluster` 時，產生的 profile 會把 `APIUrl` 留空，並把 `APIUrls` 設成此 Super，再接上各 `Cluster.Peers[].APIUrl`（依設定順序） |
| APIPrefix | API路徑前綴（必須與Super的`APIPrefix`一致） |
| NodeID | SuperNode的非特殊NodeID |
| ControlPSKey | 此Edge的HMAC簽名密鑰（必須與Super的peer entry一致） |

### Interface、LogLevel、Peers

與[Static Mode](../static_mode/README_zh.md)設定相同。在Super模式下，`Peers`列表通常為空，因為peer資訊從SuperNode下載。

## 多 Super 控制平面（active-active）

可選的 `Cluster` 區塊讓兩台以上 SuperNode 並排運作。每台 Super 都能獨立服務 Edge。Super 之間維持一條持久、加密、壓縮的 HTTP Upgrade 連線，並複製控制平面狀態。單 Super 部署省略 `Cluster`，行為與從前相同。

叢集是 eventually consistent; converges within one ReportInterval after connectivity is restored。不提供 strong consistency、leader election 或共用資料庫。Super 之間不會轉發 VPN 資料平面流量。

### 什麼會複製、什麼留在本機

會複製（依 hybrid logical clock 最後寫入獲勝）：

- 線上 Edge 紀錄（候選位址、延遲、observed-endpoint 投票、last-seen）
- Registry，包含 `ControlPSKey`
- 參數：`STUNServers`、`STUNRequestTimeoutSeconds`、`STUNRefreshIntervalSeconds`、`PollIntervalSeconds`、`ReportIntervalSeconds`、`HeartbeatIntervalSeconds`、`EventReplay`、`RelayCostMS`、`ListenPortPriority`、`EndpointBlacklist`

每台 Super 本機保留（replica apply 不會覆寫）：

- `NodeName`、`APIUrl`、`APIPrefix`、`ManagementAuth`、`Cluster`
- `PeerAliveTimeoutSeconds`、`UsePSKForInterEdge`、`DampingFilterRadius`

### Cluster

單 Super 請省略整個區塊。出現時 `SelfID` 和 `Secret` 為必填。

| Key | 預設 | 說明 |
|-----|------|------|
| SelfID | （必填） | 此 Super 的 `Vertex`。非零、非特殊，叢集內唯一 |
| Secret | （必填） | 共用的叢集 HMAC 密鑰，`json:"-"`。至少 16 bytes。不會出現在 `/manage/super/state` |
| Peers | `[]` | 叢集中的其他 Super。`SuperID` 必須唯一且不等於 `SelfID` |
| HeartbeatSeconds | 10 | 叢集連線 ping 間隔；必須為正數 |
| DeadAfterSeconds | 30 | 超過這麼多秒沒有通過驗證的 record 就視為連線死亡；必須大於 `HeartbeatSeconds` |
| ReconnectMinSeconds | 1 | 重撥 backoff 下限 |
| ReconnectMaxSeconds | 30 | 重撥 backoff 上限；必須至少等於 `ReconnectMinSeconds` |
| RemoteStaleGraceSeconds | 600 | 與遠端 Super 的連線中斷後，保留該 Super 的 live records 這麼多秒（必須至少等於 `PeerAliveTimeoutSeconds`）。填 0 時變成 `max(600, PeerAliveTimeoutSeconds)` |
| Compression | `zstd` | 內層串流壓縮：`zstd` 或 `none` |

### Cluster peers

| Key | 說明 |
|-----|------|
| SuperID | 對等 Super 的 `Vertex`。非零、非特殊，且不等於 `SelfID` |
| APIUrl | 對等 Super 的 Edge API URL（`http` 或 `https`，必須有 host）。用來撥號 `GET {APIPrefix}/cluster/link` |

可直接使用的配對：`EgNet_super_cluster_a.yaml`（SelfID 1，`http://127.0.0.1:3456`）和 `EgNet_super_cluster_b.yaml`（SelfID 2，`http://127.0.0.1:3457`）。兩邊都使用佔位密鑰 `REPLACE_WITH_32_RANDOM_CHARS`，語法上合法（`>=16` bytes），但不是生產用密鑰。

`gensuper_cluster.yaml` 是 `-mode gencfg -cfgmode super` 的產生器輸入，不是 runtime Super YAML。它會把 `Cluster` 複製進產生的 Super 設定，並讓 Edge profile 的 `APIUrls` 列出每一台 Super。產生器範例使用埠 3000/3001；上面的 runtime 配對使用 3456/3457。

### Edge failover

每個 Edge 同一時間只跟一台 Super 說話。`SuperNodeV2.APIUrls` 是 sticky failover 清單（`ResolveAPIUrls()` 在有填時把舊的 `APIUrl` 放在最前面，去掉結尾 `/`，並依先出現順序去重）。

只有 report loop 會輪換，而且只有設定了超過一個 URL 時才會：

- 連續 3 次合格的 report 失敗，或
- 在 `max(3×ReportInterval, 15s)` 內沒有任何合格成功

合格成功：Register 200、Report 2xx、Snapshot 200/304、SSE 200 connected。`ErrControlUnknownPeer` 不計入失敗次數（Edge 會改走重新註冊）。

選擇是 sticky-current：Edge 留在它輪換到的那台 Super。先前那台 Super 回來時，沒有 automatic fail-back。

Bootstrap 依序走訪 `APIUrls`，每次預算 `max(2s, remaining/len)`，並在第一台回傳合法策略的 Super 上啟動 runtime。

### 分割語意

Inter-Super 連線還在時，即使那些 Edge 沒有向本機 Super 回報，遠端 origin 的 live records 仍會保留。

連線中斷後，遠端 origin 的 records 只在 `max(receivedAt, linkDownSince)` 超過 `RemoteStaleGraceSeconds` 時才會被清掉。這次清掉是本機行為：不寫 tombstone，也不進 outbox。本機 origin 的 records 仍依 `PeerAliveTimeoutSeconds` 掃掉。

如果 Edge 在連線中斷期間換到另一台 Super，它在另一半會消失，直到連線恢復並跑完 `full_sync`。新 Super 會鑄造更新的版本；連線回來後 last-write-wins 合併會收斂成單一視圖。

### 一致性

叢集是 eventually consistent; converges within one ReportInterval after connectivity is restored。不要把 `/manage/super/state` 或 Edge snapshot 當成叢集範圍的線性化讀取。

### 安全性

Super 之間的連線使用應用層 X25519 金鑰協定、HKDF 和 ChaCha20-Poly1305 records（內層可選連續 zstd）。這是疊在反向代理已經終止的 TLS 之上的多一層防護。仍然必須透過代理提供 TLS。應用層加密不是 TLS 的替代品。Super 本身仍然只提供 HTTP。

Handshake 驗證是以 `Cluster.Secret` 為 key 的 HMAC-SHA256，簽的是 canonical string。請求路徑是這串字的一部分，所以反向代理不得改寫 `/edge/v2/cluster/link`。

### 已接受的風險

一份被截獲、已簽名的 Edge 請求，在 ±60s 時戳偏差視窗內重放到另一台 Super（兩邊時鐘再偏一點，最長大約 120s），可以重新主張該 Edge 自己的欄位和它的 observed-endpoint 投票。Edge 下一次合法 report 會鑄造更新的版本，覆蓋這次重放。影響有界，而且會自行痊癒。

### 叢集連線的 nginx Upgrade

請原樣複製這個 `location`。路徑是簽名 canonical string 的一部分，不得改寫。`proxy_read_timeout` 應至少為 `3×HeartbeatSeconds`（90s 足以覆蓋預設 10s heartbeat，並留餘量）：

```nginx
location /edge/v2/cluster/link {
    proxy_pass http://127.0.0.1:3456/edge/v2/cluster/link;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_buffering off;
    proxy_read_timeout 90s;
    proxy_send_timeout 90s;
}
```

### 診斷：`/manage/cluster/state`

`GET {APIPrefix}/manage/cluster/state?Password=<hash>` 與會改狀態的 `/manage/*` 路由一樣用 password 把關。

沒有設定 `Cluster` 時，回應本體正好是 `{"enabled":false}`。

有叢集時，本體是 `clusterStatus`（沒有另外的 `enabled` 欄位）：

```json
{
  "self_id": 1,
  "links": [
    {
      "super_id": 2,
      "api_url": "http://127.0.0.1:3457",
      "state": "connected",
      "dialer": true,
      "compression": "zstd",
      "connected_since": "2026-09-16T00:00:00Z",
      "last_rx_at": "2026-09-16T00:00:00Z",
      "last_full_sync_at": "2026-09-16T00:00:00Z",
      "tx": {"messages": 0, "inner_bytes": 0, "compressed_bytes": 0, "wire_bytes": 0},
      "rx": {"messages": 0, "inner_bytes": 0, "compressed_bytes": 0, "wire_bytes": 0}
    }
  ],
  "hlc": 0,
  "outbox_len": 0,
  "live_records": 0,
  "registry_entries": 0
}
```

`state` 為 `connected`、`connecting` 或 `down`。`/manage/super/state` 不變，仍會隱藏 `Cluster.Secret`。

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
| `gensuper_cluster.yaml` | 兩台 Super 叢集的產生器輸入（不是 runtime Super YAML） |
| `EgNet_super.yaml` | 產生的SuperNode v2設定 |
| `EgNet_super_cluster_a.yaml` | Super A 的 runtime 範例（`Cluster.SelfID` 1） |
| `EgNet_super_cluster_b.yaml` | Super B 的 runtime 範例（`Cluster.SelfID` 2） |
| `EgNet_edge001.yaml` | 產生的EdgeNode 1 v2設定 |
| `EgNet_edge002.yaml` | 產生的EdgeNode 2 v2設定 |
| `EgNet_edge100.yaml` | 產生的EdgeNode 100 v2設定 |

## 下一步：[P2P Mode](../p2p_mode/README_zh.md)
