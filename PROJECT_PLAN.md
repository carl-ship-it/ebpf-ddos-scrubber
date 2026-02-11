# eBPF L3/L4 DDoS 流量清洗設備 — 完整專案規劃

> **文件版本：** v1.0
> **日期：** 2026-02-11
> **狀態：** 規劃階段
> **團隊：** 產品經理 / 後端架構師 / 前端工程師 / 系統設計師 / 測試工程師

---

## 目錄

- [第一部分：產品規劃（產品經理）](#第一部分產品規劃)
- [第二部分：後端技術架構（後端架構師）](#第二部分後端技術架構)
- [第三部分：前端管理介面（前端工程師）](#第三部分前端管理介面)
- [第四部分：系統架構與部署（系統設計師）](#第四部分系統架構與部署)
- [第五部分：測試策略（測試工程師）](#第五部分測試策略)
- [附錄：整合摘要](#附錄整合摘要)

---

# 第一部分：產品規劃

> 負責人：產品經理

## 1. 競品分析

### 1.1 Arbor Networks (Netscout) — Arbor TMS / AED

| 分析維度 | 詳細內容 |
|---------|---------|
| **核心功能** | Arbor TMS：大規模流量清洗，支援 SYN/UDP/ICMP Flood、DNS/NTP Amplification 等全面 L3/L4 攻擊緩解。Arbor AED：部署於網路邊界的自動化威脅防禦。ATLAS 全球威脅情報平台。流量基線自動學習與異常檢測。多層聯動：雲端清洗中心 + 本地設備協同防護（Cloud Signaling） |
| **技術架構特點** | 專用硬體平台搭配軟體定義的清洗引擎。封包處理核心基於專用 ASIC/NP 加速。分散式架構，支援多台 TMS 叢集橫向擴展。Sightline 作為流量分析與指揮平台。深度封包檢測（DPI）結合流量取樣分析 |
| **部署模式** | Inline 模式（AED 主要）、旁路模式（BGP Flowspec / RTBH 牽引至 TMS）、混合模式（本地 AED + 雲端 Arbor Cloud）、GRE 隧道回注 |
| **處理能力** | TMS：單台最高約 400 Gbps，叢集可擴展至數 Tbps。AED：單台 40-100 Gbps |
| **定價模式** | 硬體一次性購買 + 年度維護與威脅情報訂閱。價格數十萬到數百萬美元 |
| **優勢** | 市場佔有率最高，品牌信任度極強（尤其電信業）。ATLAS 全球威脅情報覆蓋全球約 1/3 ISP 流量。Cloud Signaling 雲地聯防成熟 |
| **劣勢** | 價格極高。硬體綁定，升級彈性有限。管理介面較傳統，API 能力較弱。規則更新依賴韌體升級週期 |

### 1.2 Imperva — DDoS Protection

| 分析維度 | 詳細內容 |
|---------|---------|
| **核心功能** | 基礎設施 DDoS 防護（L3/L4 全協議）。Always-on 或 On-demand 兩種模式。3 秒內自動檢測與緩解（SLA）。整合 WAF、Bot 管理、CDN 的統一安全平台 |
| **技術架構特點** | 雲端清洗為核心（全球 50+ PoP）。總清洗容量 10+ Tbps。行為分析 + 規則引擎。Anycast 架構分散攻擊流量 |
| **部署模式** | 雲端清洗（BGP 牽引至 Imperva 全球清洗中心）、GRE 隧道回注、Direct Connect。無本地硬體 |
| **處理能力** | 全球清洗網路 10+ Tbps。3 秒檢測 SLA |
| **定價模式** | 訂閱制（月/年），依保護的 IP 範圍 / 子網數量 / 頻寬等級計費 |
| **優勢** | 純雲端方案，無需本地設備。全球 Anycast 天然地理分散。與 WAF/CDN 深度整合。3 秒緩解 SLA 業界領先 |
| **劣勢** | 流量需經第三方清洗，有延遲與隱私顧慮。無本地清洗能力。自訂規則靈活度不如本地設備 |

### 1.3 Radware — DefensePro

| 分析維度 | 詳細內容 |
|---------|---------|
| **核心功能** | 硬體級即時 DDoS 防護（L3/L4/L7）。BDoS 行為分析：自動學習基線，偵測零日攻擊。進階 DNS 防護、SSL/TLS Flood 防護。DefenseFlow 統一編排平台 |
| **技術架構特點** | 專用硬體 + FPGA 加速。多核心分散式架構，線速防護。機器學習行為分析引擎。與 Radware Cloud 聯動 |
| **部署模式** | Inline、旁路（BGP/GRE）、混合（本地 + 雲端）、虛擬化（vDefensePro） |
| **處理能力** | 單台最高 800 Gbps、300M PPS。FPGA 確保亞毫秒級延遲 |
| **定價模式** | 硬體一次性 + 模組化軟體授權年費。中高階型號數十萬至百萬美元 |
| **優勢** | FPGA 極低延遲與極高 PPS。BDoS 零日攻擊偵測能力強。L3-L7 全層整合。DefenseFlow 自動化優秀 |
| **劣勢** | FPGA 硬體綁定，更新受限。模組化授權成本高。管理複雜度高 |

### 1.4 競品比較總覽

| 比較項目 | Arbor TMS/AED | Imperva DDoS | Radware DefensePro | **本產品 (eBPF)** |
|---------|--------------|-------------|-------------------|------------------|
| 架構核心 | 專用 NP + 軟體 | 雲端 Anycast | FPGA 硬體加速 | **eBPF/XDP 內核態** |
| 部署形態 | 本地/混合 | 純雲端 | 本地/虛擬/混合 | **本地/雲端/容器/邊緣** |
| 最大吞吐量 | ~400 Gbps/台 | 10+ Tbps（全球） | ~800 Gbps/台 | **100+ Gbps/台** |
| 檢測延遲 | 秒級 | ~3 秒 SLA | 亞毫秒級 | **< 5 us** |
| 擴展性 | 叢集橫向 | 雲端彈性 | 叢集橫向 | **通用硬體線性擴展** |
| 初始成本 | 極高 | 低（訂閱） | 高 | **低（通用硬體）** |
| 3 年 TCO | $500K-1.2M | 中高 | 高 | **$75K-190K** |
| 規則更新 | 韌體升級（數週） | 雲端自動 | 韌體升級（數週） | **eBPF 熱更新（分鐘）** |

---

## 2. 核心功能需求（MoSCoW）

### 2.1 Must Have — P0（MVP 必備）

**L3/L4 攻擊檢測與清洗引擎：**

| 功能項 | 描述 |
|-------|------|
| SYN Flood 防護 | eBPF/XDP SYN Cookie 驗證，內核態直接丟棄偽造 SYN；支援 SYN Proxy |
| UDP Flood 防護 | 速率限制、來源驗證、payload 特徵匹配 |
| ICMP Flood 防護 | 速率限制與異常 ICMP 過濾（oversized ping、fragmented ICMP） |
| ACK Flood 防護 | 連線追蹤驗證，丟棄無對應連線的 ACK |
| DNS Amplification | 來源 port 53 + 異常回應大小比例分析 |
| NTP Amplification | NTP monlist 反射偵測，來源 port 123 異常大封包過濾 |
| SSDP/Memcached/CLDAP 反射 | 主要反射放大協議偵測與過濾 |
| IP Fragment 攻擊 | Teardrop、Fragment Flood 偵測處理 |
| 黑名單/白名單 | IP/CIDR，eBPF Map O(1) 查詢 |
| 速率限制引擎 | per-source-IP / per-dest-IP / per-protocol / per-port，Token Bucket |

**流量分析與基線學習：**

| 功能項 | 描述 |
|-------|------|
| 即時流量統計 | PPS、BPS、連線數，per-protocol / per-port |
| 流量基線自動學習 | 7 天滑動視窗，時間序列基線 |
| 異常偵測引擎 | 基線偏差自動攻擊偵測，可配置敏感度 |

**即時監控與告警：**

| 功能項 | 描述 |
|-------|------|
| Web Dashboard | 即時流量、攻擊狀態、Top-N 統計 |
| 告警通知 | Email、Webhook、Syslog |
| 攻擊事件記錄 | 完整時間軸（起止時間、類型、峰值、清洗量） |

**策略管理：**

| 功能項 | 描述 |
|-------|------|
| 策略 CRUD | 建立、修改、刪除、啟停 |
| 策略優先順序 | 優先級排列與匹配邏輯 |
| Per-IP/Subnet 策略 | 不同保護對象套用不同策略 |

**部署與高可用：**

| 功能項 | 描述 |
|-------|------|
| Inline 部署 | L2 透通 Bridge 模式 |
| 旁路部署 | BGP 牽引 + GRE 回注 |
| Active-Standby HA | 雙機故障切換 < 1 秒 |

### 2.2 Should Have — P1（v1.1-v1.2）

| 功能項 | 描述 |
|-------|------|
| GeoIP 過濾 | 國家/地區級別封鎖 |
| BGP Flowspec | 下發過濾規則至上游路由器 |
| 連線追蹤最佳化 | 千萬級並行連線 |
| 自適應閾值 | ML 動態調整 |
| 封包取樣 | sFlow/NetFlow/IPFIX |
| RESTful API | 完整管理 API |
| CLI 工具 | 批次操作與腳本自動化 |
| 攻擊報表 | PDF/CSV 匯出 |
| SNMP/Syslog | v2c/v3 監控與 Trap |
| Active-Active 叢集 | 多台負載分擔 |
| 軟體線上升級 | eBPF 熱替換零停機 |

### 2.3 Could Have — P2（v2.0）

| 功能項 | 描述 |
|-------|------|
| L7 基礎防護 | HTTP Flood 基礎偵測 |
| 自訂 eBPF 程式 | 使用者上傳自訂過濾（沙箱隔離） |
| 多租戶 | MSSP/雲端服務場景 |
| Terraform Provider | IaC 部署管理 |
| Prometheus/Grafana | 原生 metrics 匯出 |
| PCAP 擷取 | 攻擊流量鑑識分析 |
| 威脅情報 | STIX/TAXII 匯入 |
| 雲端聯防 | 上游清洗服務商 API 整合 |
| IPv6 完整支援 | 全功能 IPv6 |

### 2.4 Won't Have（明確排除）

| 功能項 | 排除理由 |
|-------|---------|
| L7 完整 WAF | 非本產品定位 |
| SSL/TLS 解密 | 影響 XDP 效能，憑證管理複雜 |
| Bot 管理 | 應用層安全範疇 |
| CDN 功能 | 避免定位混淆 |
| 自建全球清洗網路 | 專注本地/邊緣設備 |
| 專用 ASIC 開發 | 與通用硬體定位矛盾 |

---

## 3. 產品差異化定位

### 3.1 核心定位

> **以通用硬體實現專用設備效能，以軟體定義實現無限靈活性。**

### 3.2 四大差異化優勢

#### 效能優勢 — 內核態封包處理

| 指標 | 競品典型值 | 本產品目標值 | 優勢倍數 |
|------|----------|------------|---------|
| 封包處理延遲 | 50-200 us | < 5 us（XDP native） | 10-40x |
| 單核心 PPS | 1-5 Mpps | 10-24 Mpps | 5-10x |
| 單伺服器吞吐量 | 10-40 Gbps | 100+ Gbps | 3-10x |
| CPU 佔用率 | 60-90% | 10-30% | 3-5x |

#### 成本優勢 — 通用硬體

| 成本項目 | 傳統 ASIC/FPGA | eBPF 方案 | 節省 |
|---------|---------------|----------|------|
| 硬體成本（100G） | $200K-500K | $15K-40K | 80-90% |
| 年度維護 | $50K-150K | $20K-50K | 50-70% |
| 3 年 TCO | $500K-1.2M | $75K-190K | 75-85% |

#### 靈活性優勢 — 可程式化

- 傳統方案：發現新攻擊 → 廠商開發 → 韌體發布 → 停機升級（**數週到數月**）
- eBPF 方案：撰寫程式 → 驗證器檢查 → 原子替換載入（**分鐘到小時，零停機**）

#### 部署優勢 — 多場景適配

| 場景 | 傳統方案 | eBPF 方案 |
|------|---------|----------|
| 機架空間 | 專用 1-4U | 標準 1U |
| 部署時間 | 數天到數週 | 數小時 |
| 虛擬化/容器 | 有限 | 原生支援 |
| 雲端/邊緣 | 不支援 | 支援 |
| 升級方式 | 韌體停機 | eBPF 熱替換 |

### 3.3 競爭定位矩陣

```
                    高效能
                      |
     Radware          |         * 本產品
     DefensePro       |       (eBPF/XDP)
                      |
   ───────────────────+───────────────────
   高成本             |              低成本
                      |
     Arbor            |
     TMS/AED          |       Imperva
                      |       (雲端)
                      |
                    低效能(本地)
```

---

## 4. 目標客戶與使用場景

### 4.1 目標客戶

| 優先級 | 客戶群 | 痛點 | 預算 | 價值主張 |
|--------|-------|------|------|---------|
| **Tier 1** | 中大型 ISP / 電信 | Arbor TCO 過高，擴容昂貴 | $100K-$1M+ | TCO 降低 70%+，eBPF 熱更新 |
| **Tier 1** | 雲端/DC 業者 | 多租戶、API 自動化需求 | $50K-$500K | 軟體定義，API-first |
| **Tier 2** | 大型企業（金融/電商/遊戲） | 雲端延遲高，本地設備超預算 | $30K-$300K | 本地清洗低延遲，成本 1/5 |
| **Tier 2** | MSSP | 需低成本可擴展清洗平台 | $50K-$200K | 通用硬體 + 多租戶 = 最高利潤率 |
| **Tier 3** | 政府/關鍵基礎設施 | 自主可控、供應鏈安全 | 依標案 | 開放架構，無廠商鎖定 |
| **Tier 3** | 學術/研究網路 | 預算有限 | 低 | 極低成本 + 可程式化 |

### 4.2 典型使用場景

**場景一：ISP 骨幹網旁路清洗**
- BGP 路由牽引 → eBPF 叢集高速清洗 → GRE 回注
- 關鍵需求：BGP 整合、GRE 回注、叢集擴展、高吞吐

**場景二：資料中心入口 Inline 防護**
- L2 Bridge 串接，正常零延遲透通，攻擊時即時清洗
- 關鍵需求：超低延遲、Bypass、高可用

**場景三：雲端多租戶清洗平台**
- eBPF Map namespace 隔離，Self-service Portal
- 關鍵需求：多租戶、API 自動化、彈性擴展

**場景四：邊緣防護（遊戲/電商）**
- 多邊緣節點輕量 eBPF 清洗 + 中央管理
- 關鍵需求：輕量部署、集中管理、低延遲

---

## 5. MVP 定義

### 5.1 願景

> 在 6 個月內交付一套可在通用 x86 伺服器上運行的 eBPF/XDP L3/L4 DDoS 清洗系統，具備核心攻擊防護、基礎管理介面和雙機高可用。

### 5.2 MVP 效能目標

| 指標 | 目標值 |
|------|--------|
| 最大清洗吞吐量 | >= 100 Gbps |
| 最大 PPS | >= 50 Mpps (64B) |
| 清洗延遲 P99 | < 10 us |
| SYN Flood 清洗 | >= 30 Mpps |
| 誤判率 | < 0.01% |
| 漏判率 | < 1% |
| HA 切換 | < 1 秒 |
| 基線收斂 | < 7 天 |

### 5.3 MVP 團隊

| 角色 | 人數 |
|------|------|
| eBPF/XDP 核心工程師 | 3 |
| 後端工程師 (Go) | 2 |
| 前端工程師 | 1 |
| 網路工程師 | 1 |
| QA 工程師 | 1 |
| 產品經理 | 1 |
| **合計** | **9** |

### 5.4 交付時程

| 階段 | 時間 | 內容 |
|------|------|------|
| Phase 1 | Month 1 | XDP 封包處理框架、eBPF Map 結構、SYN Flood 原型、速率限制原型 |
| Phase 2 | Month 2 | 全部 L3/L4 清洗規則、基線學習引擎、異常偵測引擎 |
| Phase 3 | Month 3 | Web Dashboard、策略管理、告警引擎、CLI |
| Phase 4 | Month 4 | Inline Bridge、BGP+GRE 旁路、Active-Standby HA |
| Phase 5 | Month 5 | 100G 壓力測試、攻擊模擬驗證、安全審計 |
| Phase 6 | Month 6 | Beta 客戶試用、Bug 修復、文件完善、GA 準備 |

### 5.5 產品路線圖

```
MVP v1.0 (M1-6)        v1.1 (M7-9)          v1.2 (M10-12)        v2.0 (M13-18)
核心清洗引擎      -->   API + 整合      -->   智慧化 + 可觀測  -->  平台化 + 生態
- 10 種攻擊             - REST API             - ML 自適應           - 多租戶
- 基線學習              - Flowspec             - Prometheus          - 自訂 eBPF
- Web UI               - GeoIP                - IPv6               - Terraform
- Inline/旁路           - Active-Active        - PCAP               - 威脅情報
- A/S HA               - SNMP/Syslog          - 報表匯出           - 雲地聯防
```

### 5.6 MVP 風險

| 風險 | 影響 | 緩解 |
|------|------|------|
| XDP NIC 相容性 | 高 | 鎖定 E810 / CX-6，Phase 1 驗證 |
| eBPF verifier 限制 | 中 | tail-call 拆分，提前評估指令上限 |
| 基線誤判 | 中 | 手動 override 機制 |
| 連線追蹤記憶體 | 中 | LRU HashMap + map size 上限 |
| eBPF 人才招募 | 高 | 提前招募 + 培訓現有核心工程師 |

---

# 第二部分：後端技術架構

> 負責人：後端架構師

## 6. 整體軟體架構

### 6.1 三面分離架構

```
+================================================================+
|                    管理面 (Management Plane)                      |
|  REST API (Gin) | gRPC | CLI (Cobra) | Web UI Backend          |
+================================================================+
                              |
                         gRPC / Map R/W
                              |
+================================================================+
|                    控制面 (Control Plane)                         |
|  偵測引擎 | 策略引擎 | 基線引擎 | BGP Controller | GRE Manager   |
+================================================================+
                              |
                    eBPF Map 讀寫 + Ring Buffer
                              |
+================================================================+
|                    數據面 (Data Plane)                            |
|               XDP eBPF (第一道防線)                               |
|               TC eBPF  (第二道防線)                               |
|               eBPF Maps (共享狀態)                                |
+================================================================+
                              |
                         NIC (XDP Hook)
```

### 6.2 數據流向

```
外部流量
   |
   v
[NIC RX Queue] -- RSS 分散至多佇列
   |
   v
[XDP 層 - 第一道防線]
   |-- 黑/白名單 BPF Map 查表 --> 直接 DROP 或 PASS
   |-- SYN Cookie 驗證 (XDP_TX 回送)
   |-- 速率限制 (per-src-IP token bucket)
   |-- 封包指紋比對
   |
   v  (通過 XDP 的封包)
[TC ingress 層 - 第二道防線]
   |-- 連線追蹤 (lightweight conntrack)
   |-- 應用層啟發式檢查
   |-- 流量整形
   |-- 封包取樣 (ring_buffer --> 偵測引擎)
   |
   v  (乾淨流量)
[Linux 網路堆疊 / 轉發]
   |
   v
[TC egress 層]
   |-- 流量統計
   |-- GRE 封裝 (回注)
   |
   v
[NIC TX Queue] --> 受保護網路
```

---

## 7. eBPF/XDP 數據面設計

### 7.1 封包解析流程

```c
struct packet_context {
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct iphdr  *iph;      // or ip6hdr
    union {
        struct tcphdr  *tcp;
        struct udphdr  *udp;
        struct icmphdr *icmp;
    } l4;
    __u8  ip_proto;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u16  pkt_len;
    __u8   tcp_flags;
};
```

解析順序：`Ethernet (VLAN/QinQ) → IPv4/IPv6 → TCP/UDP/ICMP`

### 7.2 eBPF Maps 設計

| Map 名稱 | 類型 | 用途 | 大小 |
|----------|------|------|------|
| `blacklist_v4` | `LPM_TRIE` | IPv4 黑名單 (CIDR) | 1M 條目 |
| `blacklist_v6` | `LPM_TRIE` | IPv6 黑名單 | 512K |
| `whitelist` | `LPM_TRIE` | 白名單 | 256K |
| `rate_limit` | `PERCPU_HASH` | Per-IP 速率計數器 | 4M |
| `conntrack` | `LRU_PERCPU_HASH` | 連線追蹤表 | 8M |
| `syn_cookies` | `PERCPU_HASH` | SYN Cookie 狀態 | 2M |
| `attack_sigs` | `HASH` | 攻擊特徵碼 | 64K |
| `metrics` | `PERCPU_ARRAY` | Per-CPU 統計計數器 | 4096 |
| `flow_sample` | `RINGBUF` | 封包取樣環形緩衝區 | 64MB |
| `config` | `ARRAY` | 全域設定參數 | 256 |

### 7.3 關鍵資料結構

```c
// 速率限制器 (Token Bucket)
struct rate_limiter {
    __u64 tokens;           // 目前可用的 token 數
    __u64 last_refill_ns;   // 上次填充時間 (nanosecond)
    __u64 rate_pps;         // 速率限制 (packets per second)
    __u64 burst_size;       // 突發容量
    __u64 total_packets;    // 統計：總封包數
    __u64 dropped_packets;  // 統計：丟棄封包數
};

// 連線追蹤條目
struct conntrack_entry {
    __u64 last_seen_ns;     // 最後見到時間
    __u32 packets_fwd;      // 正向封包數
    __u32 packets_rev;      // 反向封包數
    __u64 bytes_fwd;        // 正向位元組數
    __u64 bytes_rev;        // 反向位元組數
    __u8  state;            // TCP 狀態 (SYN_SENT/ESTABLISHED/...)
    __u8  flags;            // 標記 (verified/suspect/...)
};

// 連線追蹤 Key (5-tuple)
struct conntrack_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   protocol;
    __u8   pad[3];
};

// 全域統計 (per-CPU)
struct global_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 dropped_packets;
    __u64 dropped_bytes;
    __u64 syn_flood_dropped;
    __u64 udp_flood_dropped;
    __u64 icmp_flood_dropped;
    __u64 acl_dropped;
    __u64 rate_limited;
    __u64 conntrack_new;
    __u64 conntrack_established;
    __u64 syn_cookies_sent;
    __u64 syn_cookies_validated;
};

// SYN Cookie 驗證
struct syn_cookie_ctx {
    __u32 cookie_seed;      // 每 60 秒輪換的密鑰
    __u32 prev_seed;        // 前一個密鑰 (輪換期間並存)
    __u64 seed_update_ns;   // 密鑰更新時間
};
```

### 7.4 攻擊檢測邏輯

**SYN Flood (SYN Cookie in XDP)：**
1. 收到 SYN → 計算 Cookie = hash(src_ip, dst_ip, src_port, dst_port, seed)
2. 構造 SYN-ACK (seq=Cookie) → XDP_TX 直接回送
3. 收到 ACK → 驗證 ack_seq-1 == hash(...)
4. 驗證通過 → 加入 conntrack，XDP_PASS 讓核心處理

**UDP Flood：**
1. Per-source-IP Token Bucket 速率限制
2. 已知反射放大特徵比對（DNS port 53 大回應、NTP port 123 monlist）
3. Payload 指紋 hash 比對已知攻擊工具

**速率限制演算法 (Token Bucket)：**
```c
static __always_inline int check_rate_limit(struct rate_limiter *rl) {
    __u64 now = bpf_ktime_get_ns();
    __u64 elapsed = now - rl->last_refill_ns;
    __u64 new_tokens = (elapsed * rl->rate_pps) / 1000000000ULL;

    rl->tokens = min(rl->tokens + new_tokens, rl->burst_size);
    rl->last_refill_ns = now;
    rl->total_packets++;

    if (rl->tokens > 0) {
        rl->tokens--;
        return PASS;
    }
    rl->dropped_packets++;
    return DROP;
}
```

---

## 8. 控制面設計

### 8.1 流量基線學習引擎

- **演算法**：EWMA (Exponentially Weighted Moving Average) + 時段分割（工作日/假日、尖峰/離峰）
- **特徵向量**：PPS、BPS、TCP/UDP/ICMP 比例、SYN 比率、平均封包大小、新連線速率、IP 熵
- **基線更新**：每分鐘更新一次，7 天滑動視窗
- **持久化**：基線模型定期序列化至磁碟，重啟後載入

### 8.2 異常檢測（多策略融合）

| 策略 | 方法 | 適用場景 |
|------|------|---------|
| Z-Score | 統計偏差檢測 | 流量突增（volumetric） |
| CUSUM | 累積和檢測 | 漸進式流量變化 |
| Entropy | 資訊熵分析 | IP/Port 分布異常 |
| Isolation Forest | 機器學習 | 複雜多維度異常 |

融合機制：各策略獨立產出異常分數 (0-100)，加權平均後判定等級。

### 8.3 動態規則下發

```
控制面偵測到攻擊
    |
    v
決策引擎選擇防禦動作
    |
    v
規則編譯器：人類可讀規則 --> BPF Map key-value
    |
    v
Map Syncer：bpf_map_update_elem() 批次寫入
    |
    v
eBPF 程式下一個封包即生效（零延遲）
```

### 8.4 BGP 整合

- **BGP Daemon**：GoBGP（程式化控制，Go 原生整合）
- **引流**：偵測到攻擊 → 宣告更具體路由（/32）+ Community 65000:666
- **Flowspec**：精細引流條件（協定、埠號、封包大小）
- **RTBH**：緊急止血，向上游宣告 blackhole

---

## 9. 技術選型

| 層級 | 技術選擇 | 理由 |
|------|---------|------|
| 數據面語言 | **C** (libbpf + CO-RE) | CO-RE 跨核心版本相容，避免 BCC runtime 編譯開銷 |
| 控制面語言 | **Go** | cilium/ebpf 生態完善，GoBGP 原生整合，並發模型優秀 |
| eBPF 框架 | **cilium/ebpf** (Go) | 純 Go 實作，無 CGO 依賴，跨平台編譯 |
| 時序資料庫 | **VictoriaMetrics** | 高效寫入，Prometheus 相容，資源佔用低 |
| 關聯式資料庫 | **PostgreSQL** | 策略/使用者/審計，JSONB 支援靈活 schema |
| 快取 | **Redis** + 本地 bigcache | API 快取 + 本地 LRU |
| 訊息佇列 | **NATS** | 輕量級，適合控制面事件分發 |
| API 框架 | **Gin** (Go) | 高效能 HTTP 路由 |
| BGP | **GoBGP** | 程式化控制，Go 原生 |

---

## 10. 效能設計

| 優化項 | 方法 |
|-------|------|
| 零拷貝 | XDP 在 NIC 驅動層直接操作 DMA 緩衝區，不經過 sk_buff 分配 |
| Per-CPU Maps | 避免鎖競爭，每個 CPU 有獨立的計數器副本 |
| Batch 操作 | bpf_map_lookup_batch/update_batch 減少 syscall |
| NUMA 感知 | NIC IRQ + eBPF 程式 + BPF Map 記憶體綁定同一 NUMA node |
| Tail Call | 複雜邏輯拆分為多個 eBPF 程式串聯，避免 verifier 限制 |
| JIT | eBPF JIT 編譯為原生機器碼，零解釋開銷 |

**效能估算：**

| 指標 | 8 核心 | 16 核心 | 備註 |
|------|--------|---------|------|
| PPS (64B, XDP_DROP) | ~70 Mpps | ~130 Mpps | 含 3-5 次 Map 查表 |
| PPS (512B) | ~45 Mpps | ~80 Mpps | |
| 最大吞吐 (bps) | ~100 Gbps | ~200 Gbps | 取決於 NIC |

---

## 11. 核心模組清單

### 11.1 數據面模組 (C, eBPF)

| 模組 | 檔案 | 職責 |
|------|------|------|
| xdp_main | `xdp_main.c` | XDP 主入口，串聯所有處理階段 |
| parser | `parser.h` | L2-L4 封包解析，填充 packet_context |
| acl_lookup | `acl.h` | 黑白名單 LPM Trie 查詢 |
| syn_flood | `syn_flood.h` | SYN Cookie 計算/驗證/回送 |
| udp_flood | `udp_flood.h` | UDP 速率限制、反射特徵偵測 |
| icmp_flood | `icmp_flood.h` | ICMP 速率限制與類型過濾 |
| ack_flood | `ack_flood.h` | ACK 合法性驗證 |
| fragment | `fragment.h` | IP 分片追蹤與異常偵測 |
| rate_limiter | `rate_limiter.h` | Token Bucket Per-CPU 無鎖實作 |
| conntrack | `conntrack.h` | 輕量連線追蹤 + TCP 狀態機 |
| fingerprint | `fingerprint.h` | Payload 指紋 hash + 特徵庫比對 |
| gre_encap | `gre_encap.h` | GRE 封裝/解封裝 |
| stats | `stats.h` | Per-CPU 計數器 + Ring Buffer 事件 |
| maps_def | `maps.h` | 所有 eBPF Maps 統一定義 |
| helpers | `helpers.h` | checksum、jhash、邊界檢查 |

### 11.2 控制面模組 (Go)

| 模組 | 套件路徑 | 職責 |
|------|----------|------|
| stats_collector | `pkg/stats/` | 輪詢 Per-CPU Maps，聚合統計 |
| ringbuf_reader | `pkg/events/` | 消費 Ring Buffer 事件 |
| baseline_engine | `pkg/baseline/` | EWMA 基線學習 |
| anomaly_detector | `pkg/anomaly/` | 多策略異常檢測 |
| decision_engine | `pkg/decision/` | 自動防禦動作生成 |
| rule_compiler | `pkg/rules/` | 規則編譯為 BPF Map 格式 |
| map_syncer | `pkg/syncer/` | Batch Map Update |
| bgp_controller | `pkg/bgp/` | GoBGP 整合、Flowspec |
| gre_manager | `pkg/tunnel/` | GRE Tunnel 管理 |
| conntrack_gc | `pkg/conntrack/` | 連線追蹤垃圾回收 |
| geoip_updater | `pkg/geoip/` | MaxMind GeoLite2 更新 |
| fingerprint_mgr | `pkg/fingerprint/` | 攻擊指紋庫管理 |
| secret_rotator | `pkg/crypto/` | SYN Cookie 密鑰輪換 |

### 11.3 管理面模組 (Go)

| 模組 | 套件路徑 | 職責 |
|------|----------|------|
| api_server | `cmd/api/` | REST API (Gin) + gRPC |
| config_manager | `pkg/config/` | YAML 配置管理 |
| policy_engine | `pkg/policy/` | 策略 CRUD + 模板 |
| alert_manager | `pkg/alert/` | 告警規則 + 多通道通知 |
| audit_logger | `pkg/audit/` | 審計日誌 |
| report_generator | `pkg/report/` | PDF/CSV 報表 |
| user_manager | `pkg/auth/` | RBAC + LDAP/OIDC |
| cli_tool | `cmd/cli/` | CLI (Cobra) |

---

# 第三部分：前端管理介面

> 負責人：前端工程師

## 12. 前端技術選型

| 項目 | 選擇 | 理由 |
|------|------|------|
| 框架 | **React 18+ (TypeScript)** | 生態最完善，Concurrent Rendering 適合高頻即時更新 |
| UI 元件庫 | **Ant Design 5.x** | 暗色主題、Table/Form 成熟、Pro Components |
| 圖表庫 | **ECharts 5.x** (主) + **D3.js** (特殊) | 大數據優化、增量更新、地理地圖 |
| 即時通訊 | **WebSocket** (主) + SSE (降級) | 雙向通訊、1s 間隔推送 |
| 狀態管理 | **Zustand** + **TanStack Query** | 全域 UI + Server State，輕量高效 |
| 建置工具 | **Vite 5.x** | 冷啟動 <300ms，HMR 即時 |

**完整技術棧：**
```
react 18.x + typescript 5.x
├── ant-design 5.x + @ant-design/pro-components
├── echarts 5.x + d3.js 7.x
├── zustand 4.x + @tanstack/react-query 5.x
├── react-router 6.x + axios + dayjs + i18next
├── vite 5.x + vitest + playwright
└── eslint + prettier
```

---

## 13. 頁面架構

### 13.1 路由結構

```
/dashboard                  總覽儀表板
/attacks                    攻擊事件列表
/attacks/:id                攻擊詳情
/attacks/trends             趨勢分析
/policies                   策略管理
/policies/templates         策略範本
/policies/network           BGP/GRE 配置
/monitoring/alerts          告警規則
/monitoring/alerts/history  告警歷史
/reports                    報表中心
/system/users               使用者管理 (RBAC)
/system/config              系統配置
/system/logs                系統日誌
/system/cluster             叢集管理
```

### 13.2 Layout 結構

```
+-------------------------------------------------------------------+
|  Top Bar: [Logo] [全域搜尋 Cmd+K] [攻擊告警鈴鐺] [系統狀態燈] [User] |
+--------+----------------------------------------------------------+
|        |                                                          |
|  Side  |   Main Content Area                                      |
|  Nav   |                                                          |
|        |   (各頁面內容)                                            |
| [儀表板] |                                                          |
| [攻擊]  |                                                          |
| [策略]  |                                                          |
| [監控]  |                                                          |
| [報表]  |                                                          |
| [系統]  |                                                          |
|        |                                                          |
|        |   Status Bar: [WS 連線] [最後更新] [叢集狀態]              |
+--------+----------------------------------------------------------+
|  Emergency Bar (攻擊時浮現):                                       |
|  [!! 攻擊中 !!] [一鍵清洗] [啟用黑洞] [查看詳情]                    |
+-------------------------------------------------------------------+
```

### 13.3 Dashboard 設計

| 區塊 | 內容 | 更新頻率 |
|------|------|---------|
| KPI 卡片 | 入站流量 / 清洗流量 / 轉發流量 / 清洗效率 / PPS / 活躍連線 | 1s |
| 即時流量趨勢圖 | Area Chart（入站/出站/清洗/丟棄） | 1s |
| 攻擊事件即時狀態 | 進行中攻擊列表 + 今日統計 | 即時 |
| 系統資源監控 | CPU/MEM/NIC/eBPF 使用率 Gauge | 5s |
| Top 10 攻擊源 | 水平柱狀圖 | 30s |
| 流量地理分布 | 世界地圖 + 散點氣泡 + 飛線動畫 | 30s |

---

## 14. 即時數據視覺化方案

### 14.1 三層更新策略

| 層級 | 指標 | 間隔 | 緩衝區 |
|------|------|------|--------|
| Tier 1 即時 | inbound_bps, outbound_bps, scrubbed_bps, pps | 1s | 300 點 (5min) |
| Tier 2 重要 | connections, cpu, memory, nic | 5s | 720 點 (1h) |
| Tier 3 統計 | top_attackers, geo, protocol | 30s | 120 點 (1h) |

### 14.2 效能優化

| 策略 | 方法 |
|------|------|
| 增量更新 | ECharts `appendData` 而非全量 setOption |
| 降採樣 | LTTB (Largest Triangle Three Buckets) 演算法 |
| 虛擬化 | dataZoom + 按需載入歷史數據 |
| Web Worker | 數據聚合/降採樣移至離屏計算 |
| Ring Buffer | 固定容量環形緩衝區，避免記憶體增長 |

### 14.3 WebSocket 協議

**頻道設計：**

| 頻道 | 內容 | 方向 |
|------|------|------|
| `traffic.realtime` | 即時流量數據 | Server → Client |
| `system.metrics` | 系統指標 | Server → Client |
| `attacks.events` | 攻擊事件通知 | Server → Client |
| `alerts.firing` | 告警觸發 | Server → Client |
| `policies.status` | 策略狀態變更 | Server → Client |

**連線管理：** 指數退避重連（1s → 2s → 4s → ... → 30s cap），序列號支援斷線補償。

---

## 15. UX 設計原則

| 原則 | 說明 |
|------|------|
| 態勢感知優先 | 第一眼判斷系統是否正常（綠/黃/紅色語意） |
| 資訊密度平衡 | 漸進式揭露：摘要 → 展開 → 深入 |
| 零驚喜原則 | 破壞性操作二次確認，高風險需輸入確認文字 |
| 可追溯性 | 所有操作有審計日誌，策略變更有 diff |
| 鍵盤友善 | Cmd+K 全域搜尋、g+d 跳轉 Dashboard |

**三級危險操作確認：**
1. **一般確認** — Modal + 確認按鈕（刪除告警規則）
2. **輸入確認** — Modal + 輸入特定文字（部署策略）
3. **雙重確認** — 輸入 + 倒計時 + MFA（啟用黑洞路由）

**暗色主題：** Ant Design 5 Dark Algorithm，品牌色 `#177ddc`，安全語意色系（嚴重度：紅/橙/黃/綠，流量：藍/綠/黃/紅）。

---

## 16. 核心元件清單

| 類別 | 元件 | 數量 |
|------|------|------|
| 通用基礎 | AppLayout, EmergencyBar, DangerConfirmModal, GlobalSearch, ConnectionStatus | 7 |
| 數據展示 | KpiCard, RealtimeTrafficChart, TrafficGaugePanel, AttackGeoMap, TopNBarChart | 10 |
| 攻擊事件 | AttackEventCard, AttackTimeline, AttackDetailPanel, AttackSourceTable | 6 |
| 策略管理 | PolicyEditor, PolicyConditionBuilder, ThresholdConfig, AclListManager, CidrInput | 9 |
| 網路配置 | BgpSessionCard, GreTunnelCard, BlackholeControl, NetworkTopology | 5 |
| 監控告警 | AlertRuleEditor, AlertNotificationToast, MetricSelector | 5 |
| 報表 | ReportGenerator, ReportPreview, ScheduleConfig, DateRangePicker | 5 |
| 系統管理 | RbacPermissionMatrix, ClusterTopologyMap, NodeDetailPanel, FirmwareUpgradeWizard | 7 |
| **合計** | | **~54** |

---

# 第四部分：系統架構與部署

> 負責人：系統設計師

## 17. 網路部署拓撲

### 17.1 Inline 部署（串接模式）

```
上游路由器 --[Port1]-- DDoS 清洗設備 --[Port2]-- 核心交換機
                        (Bridge Mode)
```

- XDP_REDIRECT 在兩張 NIC 間直接轉發，不經核心堆疊
- 管理介面獨立 out-of-band

**三級 Bypass 機制：**

| 層級 | 機制 | 觸發條件 | 切換時間 |
|------|------|---------|---------|
| L1 硬體 | 光/電 Bypass 網卡 (Silicom) | 斷電、OS 當機 | < 10ms |
| L2 Watchdog | 核心 watchdog 觸發 relay | eBPF 異常、CPU 鎖死 | < 50ms |
| L3 軟體 | XDP 切換為 XDP_PASS | 手動、系統過載 | < 1ms |

**延遲預算：**

| 場景 | 延遲 |
|------|------|
| XDP 快速路徑（黑/白名單命中） | < 1 us |
| XDP 完整檢查 | < 5 us |
| TC 深度檢查 | < 20 us |
| 端到端（含 NIC） | < 50 us |

### 17.2 Out-of-path 部署（旁路模式）

```
Internet --> ISP --> Border Router --+--> 正常流量直通
                                     |
                                     +--> (攻擊時 BGP 引流)
                                     |
                                     +--> eBPF 清洗叢集
                                              |
                                              v (GRE 回注乾淨流量)
                                     Core Network --> 目標伺服器
```

**引流方式：**
- **BGP Community**：宣告 /32 更具體路由 + Community 65000:666
- **BGP Flowspec**：精細條件（dst IP + protocol + port + pkt-length）
- **RTBH**：緊急止血，犧牲目標 IP 可用性

**GRE 回注：** TC egress 層 `bpf_skb_set_tunnel_key()` + `bpf_skb_adjust_room()`

### 17.3 混合部署（雲端 + 本地）

```
Internet --> Cloud PoP (Anycast) --> ISP --> 本地 eBPF 清洗 --> Core Network
              (容量級清洗)                    (精細清洗)
              - 吸收 >100Gbps                - 誤判修正
              - SYN Flood                    - 客製規則
```

分層：ISP (Tbps RTBH) → Cloud (100+Gbps) → On-Premise (10-100G) → Host (L7 WAF)

---

## 18. 高可用設計

### 18.1 Active-Standby

- VRRP (keepalived) 管理 VIP 漂移
- BPF Map 狀態持續同步至 Standby
- 切換時載入同步的 Map，有狀態切換
- 目標切換時間 < 3 秒

### 18.2 Active-Active

- ECMP / Resilient ECMP 分流
- 所有節點同時處理流量
- Gossip protocol 狀態同步

### 18.3 Session 同步策略

| Map 類型 | 同步方式 | 頻率 |
|----------|---------|------|
| conntrack | 增量同步 (新建/關閉) | 即時 (<100ms batch) |
| blacklist/whitelist | 變更事件 | 即時 |
| rate_limit | 摘要彙總 | 每 1 秒 |
| syn_cookies | 不同步 | N/A（無狀態） |
| attack_sigs | 全量 | 變更時 |

同步通道：專用介面，UDP + HMAC-SHA256，每 10ms 或 1000 筆批次發送，LZ4 壓縮。

### 18.4 三層健康檢查

| 層級 | 頻率 | 檢查項 |
|------|------|--------|
| L1 硬體 | 1s | NIC link、CPU 溫度、ECC 錯誤、SMART |
| L2 服務 | 3s | eBPF 程式載入、Map 讀寫、偵測引擎回應、BGP 鄰居 |
| L3 資料面 | 5s | 探測封包端到端、計數器增量、延遲、丟包率 |

---

## 19. 硬體需求規格

### 19.1 推薦伺服器

**入門級（10 Gbps）：**
```
CPU:  Intel Xeon Gold 6326 x1 (16C/32T)
RAM:  64 GB DDR4-3200 ECC
NIC:  Intel X710-DA4 (4x10G) + 1GbE 管理口
SSD:  480GB NVMe x2 (RAID-1) + 1.92TB (Log)
PSU:  550W 冗餘 x2
Form: 1U
Cost: $8,000 - $12,000
```

**標準級（100 Gbps）：**
```
CPU:  Intel Xeon Gold 6438Y+ x2 (64C/128T)
RAM:  256 GB DDR5-4800 ECC (全通道)
NIC:  Intel E810-CQDA2 x2 (4x100G) + Silicom Bypass + 10GbE HA
SSD:  960GB NVMe x2 (RAID-1) + 3.84TB (Log/PCAP)
PSU:  1200W 鉑金冗餘 x2
Form: 2U
Cost: $25,000 - $40,000
```

**高階級（400 Gbps）：**
```
CPU:  AMD EPYC 9654 x2 (192C/384T)
RAM:  512 GB DDR5-4800 ECC
NIC:  Mellanox ConnectX-7 x4 (8x100G 或 4x400G) + 同步 + 管理
SSD:  1.92TB NVMe x2 (RAID-1) + 7.68TB (Log/PCAP)
PSU:  2400W 鈦金冗餘 x2
Form: 2U
Cost: $60,000 - $100,000
```

### 19.2 NIC 需求

| 特性 | 必要性 |
|------|--------|
| XDP Native Mode | **必要** |
| Multi-Queue (>= CPU 核心數) | **必要** |
| RSS (Receive Side Scaling) | **必要** |
| Flow Director / ntuple | 建議 |
| HW Timestamping | 建議 |
| 硬體 Bypass (Inline 部署) | **Inline 必要** |

**推薦型號：** Intel E810 (ice)、Mellanox ConnectX-6 Dx (mlx5)、Silicom PE3100G2DQIR (bypass)

---

## 20. 作業系統與核心

### 20.1 OS 選擇

**推薦：Ubuntu Server 24.04 LTS + Kernel 6.6 LTS**

所需 eBPF 功能：

| 功能 | 最低核心 |
|------|---------|
| XDP native mode | 4.8+ |
| LPM_TRIE | 4.11+ |
| LRU_HASH | 4.10+ |
| PERCPU_HASH | 4.6+ |
| RINGBUF | 5.8+ |
| XDP multi-buffer | 6.0+ |
| BPF kfunc | 5.13+ |
| TCX (TC eXpress) | 6.6+ |

### 20.2 核心調校重點

```bash
# BPF JIT
net.core.bpf_jit_enable=1

# 網路緩衝區
net.core.rmem_max=134217728
net.core.netdev_max_backlog=250000

# 關閉核心 syncookies/conntrack（由 eBPF 處理）
net.ipv4.tcp_syncookies=0
net.netfilter.nf_conntrack_max=0

# Huge Pages
vm.nr_hugepages=4096
vm.swappiness=1

# CPU 隔離（GRUB 參數）
# isolcpus=2-31 nohz_full=2-31 rcu_nocbs=2-31
```

### 20.3 NIC 優化

```bash
# RSS 佇列 = CPU 核心數
ethtool -L eth0 combined 32

# 關閉 GRO/LRO（XDP 不相容）
ethtool -K eth0 gro off lro off

# 增大 Ring Buffer
ethtool -G eth0 rx 8192 tx 8192

# IRQ 親和性綁定同 NUMA node
# NUMA 感知啟動服務
numactl --cpunodebind=0 --membind=0 ./detection_engine
```

---

## 21. 安全設計

| 層級 | 措施 |
|------|------|
| 網路隔離 | MGMT 與 DATA 物理分離，管理介面白名單 IP |
| 認證 | OAuth 2.0 / JWT，SSH Key + MFA (TOTP)，設備間 mTLS |
| 授權 | RBAC 六角色：Super Admin / Security Admin / Network Admin / SOC Operator / Auditor / API Service |
| 核心加固 | SELinux Enforcing，模組簽章，KASLR/SMAP/SMEP/KPTI |
| 服務加固 | 非 root 運行 (capability-based)，Systemd sandboxing |
| 更新 | A/B 分區原子更新 + dm-verity；eBPF 熱更新 < 1ms |
| 日誌 | 稽核 90 天 + 遠端永久；安全 30 天 + 遠端 1 年；鏈式 HMAC 完整性 |

---

## 22. 監控與運維

### 22.1 Prometheus 指標

```
# 流量
ddos_scrubber_rx_packets_total{interface, protocol}
ddos_scrubber_current_pps{interface, direction}
ddos_scrubber_current_bps{interface, direction}

# 清洗
ddos_scrubber_blacklist_hits_total{list_type}
ddos_scrubber_rate_limited_total{protocol}
ddos_scrubber_syn_cookie_sent_total
ddos_scrubber_conntrack_entries_current

# 效能
ddos_scrubber_xdp_processing_time_ns{quantile}
ddos_scrubber_bpf_map_usage_percent{map_name}
```

### 22.2 SNMP MIB

自訂 MIB：ddosScrubber → ddosSystem / ddosTraffic / ddosAttack / ddosTraps

### 22.3 集中管理

Central Management Console (CMC)：全域策略管理器 (Git-based)、節點管理器、全域分析器、API Gateway。多站點統一管理，攻擊情資跨站共享。

---

## 23. 網路架構圖

### 23.1 Inline 部署

```
                          Central Management Console
                                    |  MGMT Network
                  +-----------------+-----------------+
                  |                 |                 |
           +------+------+  +------+------+  +------+------+
           | ISP Router  |  | ISP Router  |  |             |
           +------+------+  +------+------+  |             |
                  |                 |         |             |
           +------+------+  +------+------+  |             |
           | Border      |  | Border      |  |             |
           | Router-A    |  | Router-B    |  |             |
           +------+------+  +------+------+  |             |
                  |                 |         |             |
         +-------+-------+        |         |             |
         |               |        |         |             |
   +-----+-----+  +-----+-----+  |  +------+------+      |
   | Scrubber  |  | Scrubber  |  |  | Scrubber    |      |
   | Node-1    |  | Node-2    |  |  | Node-3      |      |
   | (Active)  |  | (Active)  |  |  | (Standby)   |      |
   | [XDP+TC]  |  | [XDP+TC]  |  |  | [XDP+TC]    |      |
   | [Bypass]  |  | [Bypass]  |  |  | [Bypass]    |      |
   +-----+-----+  +-----+-----+  |  +------+------+      |
         |               |        |         |             |
         +-------+-------+        +---------+             |
                 |                           |             |
          +------+------+            +------+------+      |
          | Core        |---(MLAG)---| Core        |      |
          | Switch-A    |            | Switch-B    |      |
          +------+------+            +------+------+      |
                 |                          |              |
          Server Racks                Server Racks         |
```

### 23.2 單節點內部架構

```
+-------------------------------------------------------------------+
|                     DDoS Scrubber Node                              |
|                                                                     |
|  NIC-1 (Ingress)                  NIC-2 (Egress)                   |
|  [RX Queue 0..N] --XDP_REDIRECT-- [TX Queue 0..N]                 |
|        |                                                            |
|  ======|============ Kernel Space ==================================|
|        v                                                            |
|  +--XDP eBPF (第一道防線)---------------------------------------+   |
|  | 黑/白名單 | SYN Cookie | Rate Limiter | 攻擊特徵比對        |   |
|  +------|------|-------------|-------------|---------------------+   |
|         v (XDP_PASS)                                                |
|  +--TC eBPF (第二道防線)----------------------------------------+   |
|  | Conntrack | Payload Inspection | Flow Sampling -> ring_buffer|   |
|  +--------------------------------------------------------------+   |
|                                                                     |
|  +--BPF Maps-----------------------------------------------------+ |
|  | blacklist | whitelist | rate_limit | conntrack | syn_cookies   | |
|  | attack_sigs | metrics | flow_sample (ringbuf) | config        | |
|  +-------|-------------------------------------------------------+ |
|          | (read/write)                                             |
|  ======|============ User Space ====================================|
|        v                                                            |
|  +--BPF Map Manager----------------------------------------------+ |
|  | metrics -> Prometheus | ring_buffer -> 偵測引擎 | 策略 -> Maps | |
|  +---------------------------------------------------------------+ |
|                                                                     |
|  [Detection Engine] [Policy Engine] [State Sync] [REST API]        |
|  [BGP Daemon]       [SNMP Agent]    [Prometheus Exporter]          |
|                                                                     |
|  NIC-MGMT (1/10GbE) -- SSH / HTTPS / SNMP / HA Sync               |
+-------------------------------------------------------------------+
```

---

# 第五部分：測試策略

> 負責人：測試工程師

## 24. 測試策略總覽

### 24.1 測試金字塔

```
         /\
        /  \      E2E / 驗收測試 (少量，手動+自動)
       /    \
      /------\    系統測試 / 效能測試 (自動化)
     /        \
    /----------\  整合測試 (自動化)
   /            \
  /--------------\ 單元測試 (大量，自動化，BPF_PROG_TEST_RUN)
```

### 24.2 CI/CD 整合

| 階段 | 觸發 | 內容 | 環境 |
|------|------|------|------|
| Pre-commit | git commit | lint + format | 本地 |
| CI Build | PR/Push | 編譯 + 單元測試 + 整合測試 | CI Runner (BPF capable) |
| Nightly | 每日 | 效能迴歸 + 攻擊模擬 | 效能實驗室 |
| Release | 版本標記 | 全套測試 + 安全掃描 | 效能實驗室 |

---

## 25. 單元測試

### 25.1 eBPF 程式測試

使用 `BPF_PROG_TEST_RUN` 在不需真實 NIC 的情況下測試：

```go
// 範例：SYN Flood 防護測試
func TestXDP_SYNFlood_DropsSpoofedSYN(t *testing.T) {
    prog := loadXDPProgram(t, "xdp_main")

    // 構造偽造 SYN 封包
    pkt := buildTCPPacket(srcIP: "1.2.3.4", dstIP: "10.0.0.1",
                          srcPort: 12345, dstPort: 80, flags: SYN)

    ret, _, err := prog.Test(pkt)
    require.NoError(t, err)
    // 首次 SYN 應該觸發 SYN Cookie 回送 (XDP_TX)
    assert.Equal(t, XDP_TX, ret)
}
```

### 25.2 覆蓋率目標

| 模組 | 目標 |
|------|------|
| eBPF 數據面 | >= 80% (BPF_PROG_TEST_RUN) |
| Go 控制面 | >= 85% |
| Go API | >= 90% |

---

## 26. 效能測試

### 26.1 吞吐量測試 (RFC 2544)

使用二分搜尋法定位零丟包最大吞吐量：

| 封包大小 | 目標 PPS | 目標 Gbps |
|---------|---------|----------|
| 64B | >= 50M | ~26 |
| 128B | >= 40M | ~41 |
| 256B | >= 25M | ~51 |
| 512B | >= 15M | ~61 |
| 1024B | >= 10M | ~82 |
| 1518B | >= 8M | ~97 |

### 26.2 延遲測試

| 場景 | P50 目標 | P99 目標 | P999 目標 |
|------|---------|---------|----------|
| 正常流量通過 | < 3 us | < 10 us | < 50 us |
| 清洗模式 | < 5 us | < 20 us | < 100 us |

### 26.3 壓力測試

- 24 小時高負載穩定性（80% 容量）
- 72 小時長期穩定性
- 記憶體洩漏檢測（eBPF Maps + 使用者空間）
- CPU 使用趨勢（不應隨時間增長）

---

## 27. 攻擊模擬測試

### 27.1 測試工具

| 工具 | 用途 | 場景 |
|------|------|------|
| **T-Rex** (DPDK) | 主力效能 + 攻擊模擬 | 日常測試 |
| **Ixia / Spirent** | 商業級精確測試 | 正式認證 |
| **Scapy** | 自訂封包構造 | 特殊場景 |
| **hping3** | 快速攻擊模擬 | 開發調試 |

### 27.2 攻擊場景測試矩陣

| 攻擊類型 | 測試維度 | 測試用例數 |
|---------|---------|-----------|
| SYN Flood | 速率 (1M/5M/10M/30M pps)、來源 IP 數 (1K/10K/100K/1M) | 16+ |
| UDP Flood | 隨機端口 / 固定端口 / 大封包 / 小封包 | 12+ |
| ICMP Flood | 速率遞增、oversized ping、fragmented | 8+ |
| DNS Amplification | 回應大小 (512B/1KB/4KB)、速率遞增 | 8+ |
| NTP Amplification | monlist 回應模擬、速率遞增 | 6+ |
| ACK Flood | 有/無 conntrack 條目、速率遞增 | 8+ |
| RST Flood | 有/無 conntrack、spoofed | 6+ |
| Fragment 攻擊 | Teardrop / Overlapping / Tiny Fragment | 8+ |
| **混合攻擊** | SYN+UDP+DNS 同時、脈衝式 on/off | 10+ |

### 27.3 核心測試指標

| 指標 | 縮寫 | 最低標準 | 目標標準 |
|------|------|---------|---------|
| 攻擊識別率 | TPR | >= 99.0% | >= 99.9% |
| 誤判率 | FPR | < 0.1% | < 0.01% |
| 攻擊檢測時間 | TTD | < 10s | < 3s |
| 攻擊緩解時間 | TTM | < 30s | < 5s |

---

## 28. 功能測試

| 測試項 | 覆蓋內容 |
|--------|---------|
| 策略配置 | CRUD、優先級、Per-IP/Subnet、衝突檢測 |
| BGP/GRE | Session 建立/斷開、路由宣告/撤回、GRE Tunnel UP/DOWN |
| HA 切換 | Active 當機 → Standby 接管、切換時間、Session 保持 |
| API | 全端點覆蓋、認證授權、輸入驗證、錯誤處理 |
| UI | 頁面渲染、即時數據更新、RBAC 權限隔離 |
| 權限 | 各角色存取控制驗證 |

---

## 29. 安全測試

| 測試項 | 工具 |
|--------|------|
| Web 漏洞掃描 | OWASP ZAP |
| 滲透測試 | Burp Suite Pro |
| CVE/SBOM 掃描 | Trivy / Grype |
| TLS 配置 | testssl.sh |
| 設備自身 DDoS 防護 | 管理介面速率限制測試 |

---

## 30. 驗收標準

### 30.1 上線最低標準（硬性門檻）

| 類別 | 標準 |
|------|------|
| 效能 | 100Gbps 零丟包、50Mpps (64B)、P99 <10us |
| 清洗 | TPR >=99%、FPR <0.1%、TTD <10s、TTM <30s |
| 穩定 | 24h 壓力測試通過、無記憶體洩漏 |
| HA | 切換 <3s、Bypass <10ms (斷電) |
| 安全 | 無 Critical/High CVE、OWASP Top 10 通過 |
| 功能 | 全部 P0 測試用例通過率 100% |

### 30.2 目標標準（品質追求）

| 類別 | 標準 |
|------|------|
| 效能 | 130Mpps (64B)、P99 <5us |
| 清洗 | TPR >=99.9%、FPR <0.01%、TTD <3s、TTM <5s |
| 穩定 | 72h 壓力測試、99.99% uptime |

---

## 31. 測試環境

### 31.1 網路拓撲

```
[T-Rex/Ixia] --100GbE--> [Test Switch] --100GbE--> [DUT] --100GbE--> [Receiver]
                               |                     |
                          [Packet Capture]       [MGMT Network]
                                                     |
                          [BGP Router Sim] ----10GbE--+
                          [CI/Monitor Server] --------+
```

### 31.2 設備清單

| 設備 | 規格 | 數量 |
|------|------|------|
| DUT (待測) | Xeon 6354 x2, 256GB, CX-6 100GbE x2 | 2 |
| T-Rex Server | Xeon 6330 x2, 128GB, CX-6 100GbE x2, DPDK | 1 |
| 商業測試器 | Ixia XGS12-HS 或 Spirent (100GbE x4) | 1 |
| BGP 路由器 | 8C, 32GB, 10GbE, FRRouting 8.x | 1 |
| 後端模擬 | 8C, 32GB, 25GbE, nginx + iperf3 | 1 |
| 測試交換機 | 32x100GbE (port mirror) | 1 |
| CI/監控 | 16C, 64GB, Prometheus/Grafana/Jenkins | 1 |

### 31.3 CI Runner 需求

```
OS: Ubuntu 22.04 LTS
Kernel: >= 6.1 (BTF support)
Capabilities: CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN
Sysctl: net.core.bpf_jit_enable=1
Hardware: >= 4 CPU, >= 16GB RAM
Note: bare metal 或 VM (非 Container)，或使用 sysbox runtime
```

---

# 附錄：整合摘要

## A. 關鍵設計決策

| 決策項 | 選擇 | 理由 |
|--------|------|------|
| 數據面技術 | XDP + TC eBPF | 內核態線速處理，無 DPDK 複雜性 |
| 數據面語言 | C (libbpf CO-RE) | 跨核心相容，無 runtime 編譯 |
| 控制面語言 | Go (cilium/ebpf) | 純 Go 實作，無 CGO，生態完善 |
| 前端框架 | React 18 + TypeScript | 生態最完善，Concurrent Rendering |
| 黑名單結構 | LPM_TRIE | 原生 CIDR 前綴匹配 |
| 連線追蹤 | LRU_PERCPU_HASH | LRU 自動淘汰，Per-CPU 無鎖 |
| 速率限制 | Token Bucket (Per-CPU) | 精確速率控制，無原子操作開銷 |
| SYN Flood 防禦 | XDP_TX SYN Cookie | NIC 層直接回送，不消耗 conntrack |
| BGP 引流 | GoBGP (ExaBGP 備選) | 程式化控制，Go 原生整合 |
| 時序資料庫 | VictoriaMetrics | Prometheus 相容，資源佔用低 |
| HA 同步 | 自研 UDP + HMAC | 最小化同步延遲 |
| OS | Ubuntu 24.04 LTS + Kernel 6.6 | eBPF 功能完整，社群資源豐富 |

## B. 專案里程碑

| 里程碑 | 時間 | 交付物 |
|--------|------|--------|
| M1: 核心引擎原型 | Month 1 | XDP 框架 + SYN Flood 防護 + 速率限制 |
| M2: 清洗引擎完成 | Month 2 | 全部 10 種攻擊清洗 + 基線學習 |
| M3: 管理面完成 | Month 3 | Web Dashboard + 策略管理 + 告警 |
| M4: 部署能力完成 | Month 4 | Inline + BGP/GRE + Active-Standby HA |
| M5: 測試與調優 | Month 5 | 100G 壓力測試 + 攻擊模擬 + 安全審計 |
| M6: MVP GA | Month 6 | Beta 客戶試用 + Bug 修復 + 正式發布 |
| M7-9: v1.1 | Month 9 | REST API + Flowspec + Active-Active |
| M10-12: v1.2 | Month 12 | ML 自適應 + Prometheus + IPv6 |
| M13-18: v2.0 | Month 18 | 多租戶 + 自訂 eBPF + Terraform |

## C. 團隊結構

```
                    產品經理 (1)
                        |
          +-------------+-------------+
          |             |             |
     技術主管       前端主管       QA 主管
          |             |             |
   +---------+-----+   |             |
   |         |     |   |             |
  eBPF x3  Go x2  網路 x1  前端 x1  QA x1
```

**合計 9 人，6 個月 MVP。**

---

*文件結束*
