// OAD 分类（用于解码注释/精度等）
const OAD_CATEGORIES = {
    BASIC_INFO: {
        "METER_ADDRESS": { oad: "40010200", desc: "电表地址", type: "octet-string" },
        "METER_SERIAL": { oad: "40020200", desc: "电表序列号", type: "octet-string" },
        "METER_DATETIME": { oad: "40000200", desc: "电表时钟", type: "date-time" },
    },
    ENERGY_DATA: {
        "COMBINED_ACTIVE_ENERGY": { oad: "00000200", desc: "组合有功电能", type: "double-long-unsigned", unit: "kWh", scale: -2 },
        "COMBINED_ACTIVE_ENERGY_EXT": { oad: "00000400", desc: "组合有功电能(扩展)", type: "long64-unsigned", unit: "kWh", scale: -4 },
        "ACTIVE_ENERGY_TOTAL": { oad: "00100200", desc: "正向有功总电能", type: "double-long-unsigned", unit: "kWh", scale: -2 },
        "ACTIVE_ENERGY_TOTAL_EXT": { oad: "00100400", desc: "正向有功总电能(扩展)", type: "long64-unsigned", unit: "kWh", scale: -4 },
        "REVERSE_ACTIVE_ENERGY": { oad: "00200200", desc: "反向有功总电能", type: "double-long-unsigned", unit: "kWh", scale: -2 },
        "REVERSE_ACTIVE_ENERGY_EXT": { oad: "00200400", desc: "反向有功总电能(扩展)", type: "long64-unsigned", unit: "kWh", scale: -4 },
    },
    DEMAND_DATA: {
        "DEMAND_ACTIVE_TOTAL": { oad: "10100200", desc: "正向有功最大需量", type: "double-long-unsigned", unit: "kW", scale: -4 },
        "DEMAND_REVERSE_TOTAL": { oad: "10200200", desc: "反向有功最大需量", type: "double-long-unsigned", unit: "kW", scale: -4 },
    },
    VOLTAGE_CURRENT: {
        "VOLTAGE_PHASE_A": { oad: "20000200", desc: "A相计量电压", type: "long-unsigned", unit: "V", scale: -1 },
        "CURRENT_PHASE_A": { oad: "20010200", desc: "A相计量电流", type: "double-long", unit: "A", scale: -3 },
        "POWER_FACTOR": { oad: "200A0200", desc: "功率因数", type: "long", unit: "", scale: -3 },
    },
    INSTANT_POWER: {
        "ACTIVE_POWER": { oad: "20040200", desc: "有功功率(总/三相)", type: "double-long[]", unit: "W", scale: -1 },
        "REACTIVE_POWER": { oad: "20050200", desc: "无功功率(总/三相)", type: "double-long[]", unit: "var", scale: -1 },
    },
    EVENT_RECORDS: {
        "POWER_FAILURE_EVENT": { oad: "30110700", desc: "掉电事件记录", type: "octet-string", requestType: "record" },
        "METER_COVER_EVENT": { oad: "301B0400", desc: "开表盖总次数", type: "long-unsigned", unit: "次", scale: 0 },
        "METER_COVER_EVENT_RECORD": { oad: "301B0701", desc: "开表盖事件记录", type: "octet-string", requestType: "record" },
        "METER_COVER_DETAIL_DATA": { oad: "301B0201", desc: "上一次开盖详细数据", type: "structure", requestType: "normal" },
        "METER_STATUS": { oad: "20140200", desc: "电表运行状态(数组)", type: "bit-string[]" },
        "METER_STATUS_WORD1": { oad: "20140201", desc: "电表运行状态字1", type: "bit-string" },
        "METER_STATUS_WORD2": { oad: "20140202", desc: "电表运行状态字2", type: "bit-string" },
        "METER_STATUS_WORD3": { oad: "20140203", desc: "电表运行状态字3（操作类）", type: "bit-string" },
        "POWER_ABNORMAL_EVENT_COUNT": { oad: "302C0701", desc: "电源异常事件总次数", type: "structure" },
    },
    BATTERY_VOLTAGE: {
        "CLOCK_BATTERY_VOLTAGE": { oad: "20110200", desc: "时钟电池电压", type: "double-long-unsigned", unit: "V", scale: -2 },
        "POWER_DOWN_READING_BATTERY_VOLTAGE": { oad: "20120200", desc: "停电抄表电池电压", type: "double-long-unsigned", unit: "V", scale: -2 },
    },
    FREEZE_DATA: {
        "DAILY_FREEZE": { oad: "50040200", desc: "日冻结", requestType: "record" },
        "SETTLEMENT_FREEZE": { oad: "50050200", desc: "结算日冻结", requestType: "record" },
    },
    SET_PARAMETERS: {
        "AUTO_DISPLAY": { oad: "F3000500", desc: "自动轮显参数", type: "set", setType: "autoDisplay" },
    },
    PULSE_CONSTANTS: {
        "ACTIVE_PULSE_CONSTANT": { oad: "41090200", desc: "脉冲有功常数", type: "double-long-unsigned", unit: "脉冲/kWh", scale: 0 },
        "REACTIVE_PULSE_CONSTANT": { oad: "410A0200", desc: "脉冲无功常数", type: "double-long-unsigned", unit: "脉冲/kvarh", scale: 0 },
    },
    LCD_DECIMAL_DIGITS: { oad: "40070205", desc: "液晶显示电能小数位数属性a", type: "long-unsigned", unit: "digit", scale: 0 },
};

// （已移除本地编码路径所需的费率/显示类型映射与索引）
const ERROR_CODES_DATA = {
    DAR: {
        0x00: { name: "成功", level: "info", description: "操作成功" },
        0x01: { name: "硬件失效", level: "error", description: "硬件设备故障" },
        0x02: { name: "暂时失效", level: "warning", description: "暂时性故障" },
        0x03: { name: "拒绝读写", level: "error", description: "拒绝访问" },
        0x04: { name: "对象未定义", level: "error", description: "请求的对象不存在" },
        0x05: { name: "对象接口类不符合", level: "error", description: "接口类型不匹配" },
        0x06: { name: "对象不存在", level: "error", description: "对象不存在" },
        0x07: { name: "类型不匹配", level: "error", description: "数据类型不匹配" },
        0x08: { name: "越界", level: "error", description: "数据超出范围" },
        0x09: { name: "数据块不可用", level: "warning", description: "数据块暂时不可用" },
        0x0A: { name: "分帧传输已取消", level: "warning", description: "正在进行的分帧传输被取消" },
        0x0B: { name: "不处于分帧传输状态", level: "warning", description: "当前不在分帧传输阶段" },
        0x0C: { name: "块写取消", level: "warning", description: "块写操作被取消" },
        0x0D: { name: "不存在块写状态", level: "warning", description: "未处于块写状态" },
        0x0E: { name: "数据块序号无效", level: "error", description: "块序号超限或不匹配" },
        0x0F: { name: "密码错/未授权", level: "error", description: "认证失败或未授权" },
        0x10: { name: "通信速率不能更改", level: "warning", description: "当前速率不支持修改" },
        0x11: { name: "年时区数超", level: "warning", description: "年时区数量超限" },
        0x12: { name: "日时段数超", level: "warning", description: "日时段数量超限" },
        0x13: { name: "费率数超", level: "warning", description: "费率数量超限" },
        0x14: { name: "安全认证不匹配", level: "error", description: "认证数据不匹配" },
        0x15: { name: "重复充值", level: "warning", description: "检测到重复充值" },
        0x16: { name: "ESAM验证失败", level: "error", description: "ESAM 校验失败" },
        0x17: { name: "安全认证失败", level: "error", description: "安全认证失败" },
        0x18: { name: "客户编号不匹配", level: "error", description: "客户编号与设备不符" },
        0x19: { name: "充值次数错误", level: "error", description: "充值次数异常" },
        0x1A: { name: "购电超囤积", level: "warning", description: "购电量超过囤积限制" },
        0x1B: { name: "地址异常", level: "error", description: "设备地址异常" },
        0x1C: { name: "对称解密错误", level: "error", description: "对称密钥解密失败" },
        0x1D: { name: "非对称解密错误", level: "error", description: "非对称密钥解密失败" },
        0x1E: { name: "签名错误", level: "error", description: "签名校验失败" },
        0x1F: { name: "电能表挂起", level: "warning", description: "电能表处于挂起状态" },
        0x20: { name: "时间标签无效", level: "warning", description: "时间标签不存在或已过期" },
        0x21: { name: "请求超时", level: "warning", description: "请求等待超时" },
        0x22: { name: "ESAM的P1P2不正确", level: "error", description: "ESAM 指令 P1P2 错误" },
        0x23: { name: "ESAM的LC错误", level: "error", description: "ESAM 指令 LC 字段错误" },
        0xFF: { name: "其它", level: "error", description: "其他未知错误" }
    }
};

const CONFIG = { OBJECT_IDENTIFIERS: OAD_CATEGORIES, ERROR_CODES: ERROR_CODES_DATA };

function getOADInfo(fullOAD) {
    if (!fullOAD || fullOAD.length < 8) return null;
    const shortOAD = fullOAD.slice(0, 8).toUpperCase();
    for (const cat of Object.values(CONFIG.OBJECT_IDENTIFIERS)) {
        for (const info of Object.values(cat)) {
            if (info.oad === shortOAD) return info;
        }
    }
    return null;
}

module.exports = {
    OAD_CATEGORIES,
    ERROR_CODES_DATA,
    CONFIG,
    getOADInfo
};
