# node-red-zdlms

Node-RED node for parsing electric meter frames that follow DL/T 645 or DL/T 698 (DLMS/COSEM) protocols. 645/698 编解码已模块化：`lib/645.js`、`lib/698.js`。

## Install

```bash
cd ~/.node-red
npm install /Users/john/WorkSpace/node-red-zdlms
```

Restart Node-RED and look for the `zdlms-encode` / `zdlms-decode` nodes under the Function section.

## Usage (Node-RED)

- `zdlms-encode`：固定 encode，适合构造下行帧。
- `zdlms-decode`：固定 decode，适合解析上行帧。
- 两个节点均可配置 `Protocol` 为 645 / 698 / auto（默认 auto，亦可通过 `msg.protocol` 覆盖）。
- 输入：`msg.payload` 支持字符串、Buffer、对象或数组（批处理）。对象可携带 `{hex|raw}` 或 `{oad, oadHex, sa, ca...}` 等参数。
- 输出：统一格式的解析/编码结果、状态、元数据（`msg.meta`/`msg.decoding_details` 等）。

### Encode 关键参数（698 示例）
- `msg.payload.oadHex` / `oad`: OAD 编码（支持 `XXXXXXXX` / `XXXXXXXX-YYYYYYYY` 等）。
- `sa`/`address`: 服务器地址（必填，HEX，1~16 字节）。
- `ca`: 客户地址，HEX/整数。
- `service`: `get` | `action` | `connect` | `security`；默认 `get`。
- `security`: `auto`（默认）/`none`/`plain_rn`；根据 OAD 自动选择 RN。
- 其余高级参数参考 `lib/698.js` 内联注释。

### Decode
- 输入完整 645/698 帧（HEX 字符串或 Buffer）；自动剥离前导 `FE`、校验 HCS/FCS。
- 输出的 `msg.payload` 为解析后的统一对象；原始细节在 `msg.decoding_details`。

## 实现简述

- `nodes/zdlms-encode.js` / `nodes/zdlms-decode.js` 按 `msg.protocol`（或节点配置）选择 645/698 模块，并固定模式。
- 645：完整逻辑在 `lib/645.js`。
- 698：完整编解码与解析在 `lib/698.js`（含大量 OAD 适配、自动安全策略）。

## Dev notes

- Package name: `node-red-zdlms`
- Node types: `zdlms-encode`, `zdlms-decode`
- Node-RED compatibility: `>=1.3.0`

Feel free to adjust the palette icon/color and add additional configuration fields (e.g., serial port, baud rate) as your flow requires。`lib/645.js`、`lib/698.js` 可直接复用。
