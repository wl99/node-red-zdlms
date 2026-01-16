function process698(node, msg) {
// ============================================================================
// DL/T 698.45 编解码一体化函数节点 (Auto Encode/Decode) - v1.2
// ----------------------------------------------------------------------------
// 用法：
//  - 自动判定：传入表计上行完整帧（Buffer或HEX字符串），或下行 OAD 请求（如"40010200" / {oad,...}）
//  - 强制模式：msg.mode / msg.action = "encode" | "decode"
//  - 指定通信地址：msg.com_exec_addr = "123456789012"  (优先于 payload.address)
//
// 输出：
//  - 编码：msg.payload = HEX帧(大写)，msg.frame_info，msg.meta
//  - 解码：msg.payload = 标准结果或统一格式，msg.decoding_details，msg.meta
// ============================================================================

/** ===================== 工具/常量 ===================== */

// CRC-16/X-25
function crc16X25(buffer) {
    const CRC_TABLE = Uint16Array.from([
        0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF, 0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
        0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E, 0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
        0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD, 0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
        0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C, 0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
        0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB, 0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
        0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A, 0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
        0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9, 0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
        0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738, 0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
        0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7, 0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
        0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036, 0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
        0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5, 0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
        0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134, 0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
        0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3, 0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
        0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232, 0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
        0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1, 0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
        0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330, 0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
    ]);
    let crc = 0xFFFF;
    for (let i = 0; i < buffer.length; i++) {
        crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buffer[i]) & 0xFF];
    }
    crc ^= 0xFFFF;
    return crc;
}


function sanitizeHex(str) {
    return String(str || '').replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
}
function isHexString(str) {
    return /^[0-9A-Fa-f]+$/.test(str || '');
}
function looksLikeFrameHex(hex) {
    const h = sanitizeHex(hex);
    if (h.length < 4 || h.length % 2 !== 0) return false;
    const starts = h.startsWith('FEFEFEFE68') || h.startsWith('68');
    const ends = h.endsWith('16');
    return starts && ends;
}
function looksLikeOADString(s) {
    return /^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{8})?(-\d+)?$/.test(String(s || ''));
}

// A-XDR 长长度读取（支持多字节长度）
function readAxdrLength(buf, offset = 0) {
    const first = buf[offset];
    if (first === undefined) throw new Error('长度字段缺失');
    if (first < 0x80) return { len: first, size: 1 };
    const n = first & 0x7F; // 1..4
    if (n < 1 || n > 4) throw new Error(`不支持的长度字节数: ${n}`);
    if (offset + 1 + n > buf.length) throw new Error('长度字段越界');
    let len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[offset + 1 + i];
    return { len, size: 1 + n };
}

function readAxdrSegment(buffer, offset = 0) {
    if (offset >= buffer.length) return { hex: null, nextOffset: offset, length: 0 };
    const { len, size } = readAxdrLength(buffer, offset);
    offset += size;
    if (offset + len > buffer.length) throw new Error("段长度越界");
    const slice = buffer.slice(offset, offset + len);
    return { hex: slice.toString('hex').toUpperCase(), nextOffset: offset + len, length: len };
}

// 剥离前导 FE（0~4 个）
function stripFE(buf) {
    let off = 0;
    while (off < 4 && off < buf.length && buf[off] === 0xFE) off++;
    return off ? buf.slice(off) : buf;
}

// （已移除本地编码路径所需的 OAD→请求类型映射）

/** ===================== 解码：帧→APDU→业务数据 ===================== */
function createStandardResult(dataType, oad = '', rawBuffer = null) {
    return {
        dataType,
        success: false,
        metadata: { oad, unit: null, scale: null, count: 0, timestamp: new Date().toISOString() },
        value: null,
        data: null,
        raw: { hex: rawBuffer ? rawBuffer.toString('hex').toUpperCase() : '', generic: null }
    };
}
function setSuccessResult(result, data, options = {}) {
    result.success = true;
    result.data = data;
    if (options.unit) result.metadata.unit = options.unit;
    if (options.scale !== undefined) result.metadata.scale = options.scale;
    if (options.count !== undefined) result.metadata.count = options.count;
    if (options.generic) result.raw.generic = options.generic;
}
function setErrorResult(result, error) {
    result.success = false;
    result.error = error;
}
function getDarDescription(dar) {
    const errorInfo = CONFIG.ERROR_CODES?.DAR?.[dar];
    return errorInfo ? { ...errorInfo, code: dar } : { code: dar, name: `未知错误码: 0x${dar.toString(16).padStart(2, '0')}` };
}

// 冻结类数据统一格式化为 总/尖/峰/平/谷
function formatFreezeValues(rawValues = [], options = {}) {
    const scale = options.scale ?? -2;
    const unit = options.unit ?? 'kWh';
    const divisor = Math.pow(10, Math.abs(scale));
    const labels = ['总', '尖', '峰', '平', '谷'];

    const detailed = rawValues.map((raw, idx) => ({
        label: labels[idx] || `项${idx + 1}`,
        value: (Number(raw) / divisor).toFixed(Math.abs(scale)),
        unit,
        rawValue: Number(raw),
        scale
    }));

    return {
        valueArray: detailed.map(d => parseFloat(d.value)),
        detailed
    };
}

// 日/月冻结记录专用解析（设备返回记录型数据但未使用标准数据类型标记）
function parseDailyFreezeRecord(dataBuffer, oad = '50040200') {
    const title = (oad === '50040200') ? '日冻结' : (oad === '50050200' ? '结算日冻结' : '冻结数据');
    const result = createStandardResult(title, oad, dataBuffer);

    // 快速探测：长度至少包含时间戳(8B) + 计数(1B) + 至少1个 0x06 +4B 数值
    if (!dataBuffer || dataBuffer.length < 14) {
        setErrorResult(result, '数据长度不足，无法解析日冻结记录');
        return result;
    }

    // 前 8 字节时间戳，此处只保留原始值，不做解析
    const timeRaw = dataBuffer.slice(0, 8);

    const count = dataBuffer[8];
    let cursor = 9;
    const items = [];

    for (let i = 0; i < count && cursor + 5 <= dataBuffer.length; i++) {
        const type = dataBuffer[cursor++];
        if (type !== 0x06 || cursor + 4 > dataBuffer.length) break; // 0x06: double-long-unsigned
        const rawVal = dataBuffer.slice(cursor, cursor + 4);
        cursor += 4;
        const val = rawVal.readUInt32BE(0);
        items.push(val);
    }

    const { valueArray, detailed } = formatFreezeValues(items, { scale: -2, unit: 'kWh' });

    result.value = valueArray;
    setSuccessResult(result, detailed, {
        unit: 'kWh',
        scale: -2,
        count: detailed.length,
        generic: {
            timeRaw: timeRaw.toString('hex').toUpperCase(),
            trailingHex: (cursor < dataBuffer.length) ? dataBuffer.slice(cursor).toString('hex').toUpperCase() : null
        }
    });
    return result;
}

function detectAndValidateFrame(buffer) {
    if (buffer.length < 12 || buffer[0] !== 0x68 || buffer[buffer.length - 1] !== 0x16) return null;

    const declaredLength = buffer[1] | (buffer[2] << 8);
    const expectedLength = buffer.length - 2; // 按标准：长度域为除起始/结束符外的字节总数
    const fcsStart = buffer.length - 3;

    const tryStructuredParse = () => {
        if (buffer.length < 7) return null;
        const saFlagIndex = 4;
        const saFlag = buffer[saFlagIndex];
        const serverAddrLen = (saFlag & 0x0F) + 1;
        const serverAddrEnd = saFlagIndex + 1 + serverAddrLen;
        if (serverAddrEnd + 3 > fcsStart) return null;

        for (const caLen of [1, 2]) {
            const caEnd = serverAddrEnd + caLen;
            const hcsStart = caEnd;
            if (hcsStart + 2 > fcsStart) continue;

            const headerForHcs = buffer.slice(1, hcsStart);
            const calculatedHcs = crc16X25(headerForHcs);
            const receivedHcs = buffer.readUInt16LE(hcsStart);
            if (calculatedHcs !== receivedHcs) continue;

            const dataForFcs = buffer.slice(1, fcsStart);
            const calculatedFcs = crc16X25(dataForFcs);
            const receivedFcs = buffer.readUInt16LE(fcsStart);
            if (calculatedFcs !== receivedFcs) {
                throw new Error(`FCS校验失败: 计算=0x${calculatedFcs.toString(16)}, 接收=0x${receivedFcs.toString(16)}`);
            }

            const saBytes = buffer.slice(saFlagIndex + 1, serverAddrEnd);
            const caBytes = buffer.slice(serverAddrEnd, caEnd);

            return {
                apduStart: hcsStart + 2,
                fcsStart,
                address: buffer.slice(saFlagIndex, hcsStart).toString('hex').toUpperCase(),
                saFlag,
                serverAddress: saBytes.toString('hex').toUpperCase(),
                clientAddress: caBytes.toString('hex').toUpperCase(),
                declaredLength,
                lengthMatched: declaredLength === expectedLength
            };
        }
        return null;
    };

    const structuredResult = tryStructuredParse();
    if (structuredResult) return structuredResult;

    for (let addrLen = 1; addrLen <= 16; addrLen++) {
        const hcsStart = 4 + addrLen;
        if (hcsStart + 2 > fcsStart) continue;
        const headerForHcs = buffer.slice(1, hcsStart);
        const calculatedHcs = crc16X25(headerForHcs);
        const receivedHcs = buffer.readUInt16LE(hcsStart);
        if (calculatedHcs === receivedHcs) {
            const dataForFcs = buffer.slice(1, fcsStart);
            const calculatedFcs = crc16X25(dataForFcs);
            const receivedFcs = buffer.readUInt16LE(fcsStart);
            if (calculatedFcs === receivedFcs) {
                return {
                    apduStart: hcsStart + 2,
                    fcsStart,
                    address: buffer.slice(4, hcsStart).toString('hex').toUpperCase(),
                    declaredLength,
                    lengthMatched: declaredLength === expectedLength
                };
            } else {
                throw new Error(`FCS校验失败: 计算=0x${calculatedFcs.toString(16)}, 接收=0x${receivedFcs.toString(16)}`);
            }
        }
    }
    throw new Error(`HCS校验失败: 无法在任何地址长度假设下匹配HCS`);
}

// 递归解析：数组/结构体/常见类型 + A-XDR 长长度
function parseArray(data, oi, attr) {
    const count = data[0];
    let offset = 1, items = [];
    for (let i = 0; i < count; i++) {
        if (offset >= data.length) break;
        const { result, consumed } = enhancedParseData(data.slice(offset), oi, attr);
        items.push(result);
        offset += consumed;
    }
    return { parsedValue: items, consumed: offset };
}
function parseStructure(data, oi, attr) {
    const count = data[0];
    let offset = 1, items = [];
    for (let i = 0; i < count; i++) {
        if (offset >= data.length) break;
        const { result, consumed } = enhancedParseData(data.slice(offset), oi, attr);
        items.push(result);
        offset += consumed;
    }
    return { parsedValue: items, consumed: offset };
}
function enhancedParseData(dataBuffer, oi, attributeId) {
    if (!dataBuffer || dataBuffer.length === 0) return { result: { rawData: '', dataType: '空', parsedValue: null }, consumed: 0 };
    const dataType = dataBuffer[0];
    const actualData = dataBuffer.slice(1);
    const result = { rawData: '', dataType: `未知(0x${dataType.toString(16)})`, parsedValue: null };
    let consumed = 1;
    try {
        switch (dataType) {
            case 0x00: result.dataType = "空值"; result.parsedValue = null; break;
            case 0x01: {
                // 根据DL/T 698.45标准：0x01是array类型
                const r = parseArray(actualData, oi, attributeId);
                result.dataType = "数组";
                result.parsedValue = r.parsedValue;
                consumed += r.consumed;
                break;
            }
            case 0x02: { const r = parseStructure(actualData, oi, attributeId); result.dataType = "结构体"; result.parsedValue = r.parsedValue; consumed += r.consumed; break; }
            case 0x03: result.dataType = "布尔型"; result.parsedValue = actualData[0] !== 0; consumed += 1; break;
            case 0x04: {
                // 根据DL/T 698.45标准：0x04是bit-string类型
                result.dataType = "bit-string";
                if (actualData.length > 0) {
                    // 读取数据长度
                    const dataLength = actualData[0];
                    result.parsedValue = actualData.slice(1, 1 + dataLength);
                    consumed += (1 + dataLength);
                }
                break;
            }
            case 0x05: result.dataType = "双长整数"; if (actualData.length >= 4) { result.parsedValue = actualData.readInt32BE(0); consumed += 4; } break;
            case 0x06: result.dataType = "双长无符号整数"; if (actualData.length >= 4) { result.parsedValue = actualData.readUInt32BE(0); consumed += 4; } break;
            case 0x09: { // byte-string (A-XDR 长长度)
                result.dataType = "字节串";
                if (actualData.length === 0) break;
                const L = readAxdrLength(dataBuffer, 1);
                const start = 1 + L.size;
                const end = start + L.len;
                if (end > dataBuffer.length) throw new Error("字节串长度越界");
                result.parsedValue = dataBuffer.slice(start, end).toString('hex').toUpperCase();
                consumed += (L.size + L.len);
                break;
            }
            case 0x0A: { // visible-string (A-XDR 长长度)
                result.dataType = "可见字符串";
                if (actualData.length === 0) break;
                const L = readAxdrLength(dataBuffer, 1);
                const start = 1 + L.size;
                const end = start + L.len;
                if (end > dataBuffer.length) throw new Error("可见字符串长度越界");
                result.parsedValue = dataBuffer.slice(start, end).toString('utf8');
                consumed += (L.size + L.len);
                break;
            }
            case 0x10: result.dataType = "长整数"; if (actualData.length >= 2) { result.parsedValue = actualData.readInt16BE(0); consumed += 2; } break;
            case 0x11: // unsigned (8-bit)
                result.dataType = "无符号整数";
                if (actualData.length >= 1) {
                    result.parsedValue = actualData[0];
                    consumed += 1;
                }
                break;
            case 0x12: result.dataType = "长无符号整数"; if (actualData.length >= 2) { result.parsedValue = actualData.readUInt16BE(0); consumed += 2; } break;
            case 0x14: result.dataType = "64位长整数"; if (actualData.length >= 8) { result.parsedValue = actualData.readBigInt64BE(0).toString(); consumed += 8; } break;
            case 0x15: result.dataType = "64位无符号长整数"; if (actualData.length >= 8) { result.parsedValue = actualData.readBigUInt64BE(0).toString(); consumed += 8; } break;
            case 0x1C: result.dataType = "简化日期时间"; if (actualData.length >= 7) {
                const y = actualData.readUInt16BE(0);
                const m = String(actualData[2]).padStart(2, '0');
                const d = String(actualData[3]).padStart(2, '0');
                const h = String(actualData[4]).padStart(2, '0');
                const i = String(actualData[5]).padStart(2, '0');
                const s = String(actualData[6]).padStart(2, '0');
                result.parsedValue = `${y}-${m}-${d} ${h}:${i}:${s}`;
                consumed += 7;
            } break;

            
            default:
                result.parsedValue = dataBuffer.toString('hex').toUpperCase();
                consumed = dataBuffer.length; break;
        }
    } catch (e) { result.error = `解析失败: ${e.message}`; consumed = dataBuffer.length; }
    result.rawData = dataBuffer.slice(0, consumed).toString('hex').toUpperCase();
    return { result, consumed };
}

function toBigEndian16(value) {
    if (value == null) return null;
    const upper = (value >>> 8) & 0xFF;
    const lower = value & 0xFF;
    // 将小端(低字节在前)转换为大端(高字节在前)
    return (lower << 8) | upper;
}
/**
 * 解析电表运行状态字2 - 与645协议格式保持一致
 * @param {Buffer} dataBuffer - 数据缓冲区
 * @returns {Object} 解析结果
 */

function parseMeterStatus(dataBuffer, oad = '20140201') {
    const result = createStandardResult("电表状态", oad, dataBuffer);
    try {
        // 1. 读取原始状态字（小端）
        const statusWordLe = parseMeterStatusOptimized(dataBuffer);

        // 2. 转换为大端，用于大端逻辑判断
        const statusWordBe = toBigEndian16(statusWordLe);

        if (statusWordBe !== null) {
            const valTmp = statusWordBe & 0xFFFF;
            const bin = valTmp.toString(2).padStart(16, '0'); // 最高位bit15在最左

            // 3. 大端判断：bit0 是最左边的最高位
            result.value = {
                rawValue: valTmp,
                binary: bin,
                keys: {
                    'bit15 时钟故障':     bin[0]  === '1',
                    'bit14 透支状态':     bin[1]  === '1',
                    'bit13 存储器故障或损坏': bin[2]  === '1',
                    'bit12 内部程序错误': bin[3]  === '1',
                    'bit11 保留':         bin[4]  === '1',
                    'bit10 保留':         bin[5]  === '1',
                    'bit9  ESAM错误':     bin[6]  === '1',
                    'bit8  控制回路错误': bin[7]  === '1',
                    'bit7  保留':         bin[8]  === '1',
                    'bit6  保留':         bin[9]  === '1',
                    'bit5  无功功率方向反向': bin[10] === '1',
                    'bit4  有功功率方向反向': bin[11] === '1',
                    'bit3  停电抄表电池欠压': bin[12] === '1',
                    'bit2  时钟电池欠压': bin[13] === '1',
                    'bit1  需量积算方式': bin[14] === '1',
                    'bit0  保留':         bin[15] === '1'
                }
            };

            setSuccessResult(result, {
                timestamp: null,
                statusWord: valTmp,
                statusWordHex: valTmp.toString(16).padStart(4, '0').toUpperCase(),
                statusBits: decodeMeterStatusBits(valTmp)
            }, { generic: { dataType: 'bit-string' } });
        } else {
            throw new Error("无法解析状态字");
        }

    } catch (e) {
        console.error('parseMeterStatus错误:', e.message);
        setErrorResult(result, e.message);
    }

    return result;
}


/**
 * 解析电表运行状态字3（20140203）- 按操作类位义输出字段
 */
function parseMeterStatusWord3(dataBuffer) {
    const oad = '20140203';
    const result = createStandardResult("电表运行状态字3", oad, dataBuffer);
    try {
        const statusWord = parseMeterStatusOptimized(dataBuffer);
        if (statusWord === null) throw new Error('无法解析状态字');

        const val16 = statusWord & 0xFFFF; // 低16位
        const bin = val16.toString(2).padStart(16, '0');

        const supplyBits = (val16 >> 1) & 0b11; // bit2-bit1
        const supplyMode = (
            supplyBits === 0 ? '主电源' :
            supplyBits === 1 ? '辅助电源' :
            supplyBits === 2 ? '电池供电' : '保留'
        );

        const meterTypeBits = (val16 >> 8) & 0b11; // bit9-bit8
        const meterType = (
            meterTypeBits === 0 ? '非预付费表' :
            meterTypeBits === 1 ? '电量型预付费表' :
            meterTypeBits === 2 ? '电费型预付费表' : '保留'
        );

        result.value = {
            rawValue: val16,
            binary: bin,
            fields: {
                当前运行时段套数: (val16 & 0x1) ? '第二套' : '第一套',
                供电方式: supplyMode,                              // bit2-bit1
                编程允许状态: (val16 & (1 << 3)) ? '有效' : '失效',   // bit3
                继电器状态: (val16 & (1 << 4)) ? '断' : '通',        // bit4（线路实际工作状态）
                当前运行时区套数: (val16 & (1 << 5)) ? '第二套' : '第一套',
                继电器命令状态: (val16 & (1 << 6)) ? '断' : '通',    // bit6（远程拉闸命令）
                预跳闸报警状态: (val16 & (1 << 7)) ? '有' : '无',    // bit7
                电能表类型: meterType,                              // bit9-bit8
                当前运行分时费率套数: (val16 & (1 << 10)) ? '第二套' : '第一套',
                当前阶梯套数: (val16 & (1 << 11)) ? '第二套' : '第一套',
                保电状态: (val16 & (1 << 12)) ? '保电' : '非保电'
            }
        };

        setSuccessResult(result, {
            statusWord: val16,
            statusWordHex: val16.toString(16).padStart(4, '0').toUpperCase(),
            statusBits: decodeMeterStatusBits(val16)
        }, { generic: { dataType: 'bit-string' } });
    } catch (e) {
        setErrorResult(result, e.message);
    }
    return result;
}

/**
 * 解析电表运行状态字2（20140202）- 返回原始位数组，不强加语义
 */
function parseMeterStatusWord2(dataBuffer) {
    const oad = '20140202';
    const result = createStandardResult("电表运行状态字2", oad, dataBuffer);
    try {
        const statusWord = parseMeterStatusOptimized(dataBuffer);
        if (statusWord === null) throw new Error('无法解析状态字');

        const val16 = statusWord & 0xFFFF;
        const bin = val16.toString(2).padStart(16, '0');

        const bit = (n) => ((val16 >> n) & 0x1);
        const dir = (b) => (b ? '反向' : '正向'); // 0=正向, 1=反向

        // 按表F.2位义生成具名字段
        const fields = {
            'A相有功功率方向': dir(bit(0)), // bit0
            'B相有功功率方向': dir(bit(1)), // bit1
            'C相有功功率方向': dir(bit(2)), // bit2
            'A相无功功率方向': dir(bit(4)), // bit4
            'B相无功功率方向': dir(bit(5)), // bit5
            'C相无功功率方向': dir(bit(6))  // bit6
            // 其余bit3、bit7、bit8~bit15为保留
        };

        result.value = {
            rawValue: val16,
            binary: bin,
            bits: decodeMeterStatusBits(val16),
            fields
        };

        setSuccessResult(result, { statusWord: val16, statusWordHex: val16.toString(16).padStart(4, '0').toUpperCase(), statusBits: decodeMeterStatusBits(val16) }, { generic: { dataType: 'bit-string' } });
    } catch (e) {
        setErrorResult(result, e.message);
    }
    return result;
}

/**
 * 优化的状态字解析策略
 * @param {Buffer} dataBuffer - 数据缓冲区
 * @returns {number|null} 状态字或null
 */
function parseMeterStatusOptimized(dataBuffer) {
    // 策略1: 直接解析Security-Response结构
    let statusWord = parseSecurityResponseStructure(dataBuffer);
    if (statusWord !== null) return statusWord;

    // 策略2: 使用enhancedParseData
    statusWord = parseWithEnhancedParser(dataBuffer);
    if (statusWord !== null) return statusWord;

    return null;
}

/**
 * 解析Security-Response结构
 * @param {Buffer} dataBuffer - 数据缓冲区
 * @returns {number|null} 状态字或null
 */
function parseSecurityResponseStructure(dataBuffer) {
    if (dataBuffer.length < 3) return null;

    const firstByte = dataBuffer[0];
    if (firstByte !== 0x90) return null; // Security-Response

    const plainLength = dataBuffer[1];
    if (plainLength === 0 || plainLength + 2 > dataBuffer.length) return null;

    const plainContent = dataBuffer.slice(2, 2 + plainLength);
    return parsePlainContent(plainContent);
}

/**
 * 解析明文内容
 * @param {Buffer} plainContent - 明文内容
 * @returns {number|null} 状态字或null
 */
function parsePlainContent(plainContent) {
    if (plainContent.length < 8) return null; // 最小长度检查

    try {
        let offset = 0;

        // APDU类型 (2字节)
        const apduType = plainContent.readUInt16BE(offset);
        offset += 2;

        // PIID (1字节)
        const piid = plainContent[offset];
        offset += 1;

        // OAD (4字节)
        const oad = plainContent.slice(offset, offset + 4).toString('hex').toUpperCase();
        offset += 4;

        // 数据类型 (1字节)
        if (offset >= plainContent.length) return null;
        const dataType = plainContent[offset];
        offset += 1;

        // 数据长度 (1字节)
        if (offset >= plainContent.length) return null;
        const dataLength = plainContent[offset];
        offset += 1;

        // 数据内容
        if (offset + dataLength > plainContent.length) return null;
        const dataContent = plainContent.slice(offset, offset + dataLength);

        // 尝试解析状态字
        if (dataType === 0x01 && dataLength >= 4) { // array类型
            return parseArrayStatusWord(dataContent);
        } else if (dataType === 0x04 && dataLength >= 4) { // bit-string类型
            return dataContent.readUInt32LE(0);
        }

    } catch (error) {
        console.error('解析明文内容失败:', error.message);
    }

    return null;
}

/**
 * 解析数组中的状态字
 * @param {Buffer} arrayData - 数组数据
 * @returns {number|null} 状态字或null
 */
function parseArrayStatusWord(arrayData) {
    if (arrayData.length < 1) return null;

    const elementCount = arrayData[0];
    let offset = 1;

    for (let i = 0; i < elementCount && offset < arrayData.length; i++) {
        if (offset + 2 > arrayData.length) break;

        const elementType = arrayData[offset];
        const elementLength = arrayData[offset + 1];
        offset += 2;

        if (offset + elementLength > arrayData.length) break;

        const elementData = arrayData.slice(offset, offset + elementLength);

        // 查找bit-string类型的元素
        if (elementType === 0x04 && elementLength >= 4) { // bit-string
            return elementData.readUInt32LE(0);
        }

        offset += elementLength;
    }

    return null;
}

/**
 * 使用enhancedParseData解析
 * @param {Buffer} dataBuffer - 数据缓冲区
 * @returns {number|null} 状态字或null
 */
function parseWithEnhancedParser(dataBuffer) {
    try {
        const { result: genericResult } = enhancedParseData(dataBuffer, '2014', '02');

        if (genericResult.dataType === 'bit-string') {
            // 直接bit-string类型
            if (dataBuffer.length >= 4) {
                return dataBuffer.readUInt32LE(0);
            }
        } else if (genericResult.dataType === '数组') {
            // 数组类型，查找bit-string元素
            if (genericResult.parsedValue && Array.isArray(genericResult.parsedValue)) {
                for (const item of genericResult.parsedValue) {
                    if (item.dataType === 'bit-string' && item.parsedValue && item.parsedValue.length >= 4) {
                        return item.parsedValue.readUInt32LE(0);
                    }
                }
            }
        }

    } catch (error) {
        console.error('enhancedParseData解析失败:', error.message);
    }

    return null;
}

/**
 * 专门解析电表运行状态字2的函数 - 简化版本，只返回0、1位值数组
 * @param {number} statusWord - 32位状态字
 * @returns {Array} 状态位原始值数组（0或1），从bit0到bit31
 */
function decodeMeterStatusBits(statusWord) {
    const bits = [];

    // 从bit0到bit31，生成32个位的值
    for (let i = 0; i < 32; i++) {
        const mask = 1 << i;
        bits.push((statusWord & mask) ? 1 : 0);
    }

    return bits;
}

// 已废弃：旧的“掉电事件记录”解析函数，改为专用 30110700 记录数解析

/**
 * 解析 电能表掉电事件-当前记录数 (30110700)
 * 对齐C#代码：读取“当前记录数”并返回整数。兼容多种返回封装（纯数值/结构体/数组）。
 */
function parsePowerFailureEventCount(dataBuffer) {
    const oad = '30110700';
    const result = createStandardResult("电能表掉电事件-当前记录数", oad, dataBuffer);
    try {
        // 通用解析
        const { result: generic } = enhancedParseData(dataBuffer, '3011', '07');

        // 递归提取首个整型值（优先16/32/64位无符号，再退化到有符号/8位）
        function findFirstInteger(parsed) {
            if (!parsed || typeof parsed !== 'object') return null;
            const dt = parsed.dataType;
            const val = parsed.parsedValue;
            const isNumber = (v) => typeof v === 'number' && Number.isFinite(v);
            const preferUnsignedTypes = new Set([
                '长无符号整数',       // 0x12, UInt16
                '双长无符号整数',     // 0x06, UInt32
                '64位无符号长整数',   // 0x15, UInt64 (以字符串输出时已转string,此处跳过)
                '无符号整数'          // 0x11, UInt8
            ]);

            // 直接节点
            if (preferUnsignedTypes.has(dt) && isNumber(val)) return val;
            if ((dt === '长整数' || dt === '双长整数') && isNumber(val)) return val; // 容忍有符号

            // 结构/数组递归
            if (Array.isArray(parsed.parsedValue)) {
                for (const item of parsed.parsedValue) {
                    const got = findFirstInteger(item);
                    if (got !== null) return got;
                }
            }
            return null;
        }

        let count = findFirstInteger(generic);

        // 额外容错：若解析不到，但payload很短，尝试直接按UInt16/UInt32读取
        if (count === null) {
            try {
                if (dataBuffer.length >= 3 && dataBuffer[0] === 0x12) {
                    // long-unsigned: tag(0x12) + 2 bytes
                    count = dataBuffer.readUInt16BE(1);
                } else if (dataBuffer.length >= 5 && dataBuffer[0] === 0x06) {
                    // double-long-unsigned: tag(0x06) + 4 bytes
                    count = dataBuffer.readUInt32BE(1);
                }
            } catch (_) { /* ignore */ }
        }

        if (count === null) {
            throw new Error('未能在返回数据中识别出记录数');
        }

        result.value = count;
        setSuccessResult(result, [{ label: '当前记录数', value: count }], { unit: null, scale: 0, count: 1, generic });
    } catch (e) {
        setErrorResult(result, e.message);
    }
    return result;
}

/**
 * 解析 电源异常事件总次数 (302C0701)
 * 兼容多厂商格式：可能返回结构体/数组嵌套的一个或多个无符号长整数。
 * value: 返回总次数（若存在多个数值则求和），data: 列出拆解项
 */
function parsePowerAbnormalCount(dataBuffer) {
    const oad = '302C0701';
    const result = createStandardResult("电源异常事件总次数", oad, dataBuffer);
    try {
        const { result: generic } = enhancedParseData(dataBuffer, '302C', '07');

        const nums = [];
        function collect(node, depth = 0) {
            if (!node || depth > 8) return;
            if (typeof node === 'number') { nums.push(node); return; }
            if (Array.isArray(node)) { for (const it of node) collect(it, depth + 1); return; }
            if (typeof node === 'object') {
                if (typeof node.parsedValue === 'number') nums.push(node.parsedValue);
                collect(node.parsedValue, depth + 1);
                if (node.value && node.value !== node.parsedValue) collect(node.value, depth + 1);
                if (node.data && node.data !== node.parsedValue && node.data !== node.value) collect(node.data, depth + 1);
            }
        }
        collect(generic);

        // 明确两项：总次数 与 清零/复位次数（若存在）
        const total = (nums.length >= 1) ? nums[0] : null;
        const reset = (nums.length >= 2) ? nums[1] : null;

        // 为兼容旧用法：把 value 结构化，但“count”默认取 total
        result.value = { total, reset, parts: nums };
        setSuccessResult(result, [{ type: '电源异常事件总次数', total, reset, parts: nums }], { count: nums.length, generic });
    } catch (e) { setErrorResult(result, e.message); }
    return result;
}

/**
 * 解析开表盖总次数 - 基于实际698协议数据格式
 * @param {Buffer} dataBuffer - 数据缓冲区
 * @returns {Object} 解析结果
 */
function parseMeterCoverEvent(dataBuffer) {
    const result = createStandardResult("开表盖总次数", '301B0400', dataBuffer);

    try {
        // 根据实际数据帧分析，开表盖总次数是长无符号整数类型（2字节）
        const { result: genericResult } = enhancedParseData(dataBuffer, '301B', '04');

        if (genericResult.dataType === '长无符号整数') {
            // 直接使用enhancedParseData已经正确解析的值
            const coverCount = Number(genericResult.parsedValue);
            result.value = coverCount;

            setSuccessResult(result, [{
                type: "开表盖总次数",
                count: coverCount,
                unit: "次",
                rawValue: coverCount,
                description: `电表开盖总次数为 ${coverCount} 次`
            }], {
                unit: "次",
                scale: 0,
                count: 1,
                generic: genericResult
            });

        } else if (genericResult.dataType === '双长无符号整数') {
            // 兼容4字节格式（如果某些设备使用）
            const coverCount = Number(genericResult.parsedValue);
            result.value = coverCount;

            setSuccessResult(result, [{
                type: "开表盖总次数",
                count: coverCount,
                unit: "次",
                rawValue: coverCount,
                description: `电表开盖总次数为 ${coverCount} 次`
            }], {
                unit: "次",
                scale: 0,
                count: 1,
                generic: genericResult
            });

        } else if (genericResult.dataType === '数组') {
            // 如果是数组格式，取第一个元素
            if (genericResult.parsedValue && genericResult.parsedValue.length > 0) {
                const firstItem = genericResult.parsedValue[0];
                if (firstItem.dataType === '长无符号整数') {
                    // 数组中的长无符号整数
                    const coverCount = Number(firstItem.parsedValue);
                    result.value = coverCount;

                    setSuccessResult(result, [{
                        type: "开表盖总次数",
                        count: coverCount,
                        unit: "次",
                        rawValue: coverCount,
                        description: `电表开盖总次数为 ${coverCount} 次`
                    }], {
                        unit: "次",
                        scale: 0,
                        count: 1,
                        generic: genericResult
                    });
                } else if (firstItem.dataType === '双长无符号整数') {
                    // 数组中的双长无符号整数
                    const coverCount = Number(firstItem.parsedValue);
                    result.value = coverCount;

                    setSuccessResult(result, [{
                        type: "开表盖总次数",
                        count: coverCount,
                        unit: "次",
                        rawValue: coverCount,
                        description: `电表开盖总次数为 ${coverCount} 次`
                    }], {
                        unit: "次",
                        scale: 0,
                        count: 1,
                        generic: genericResult
                    });
                } else {
                    throw new Error(`数组中的数据类型不正确: ${firstItem.dataType}`);
                }
            } else {
                throw new Error("数组为空，无法解析开盖次数");
            }
        } else {
            throw new Error(`开表盖总次数数据格式不正确: ${genericResult.dataType}`);
        }

    } catch (e) {
        setErrorResult(result, e.message);
    }

    return result;
}

/**
 * 解析开表盖事件记录 - 基于实际698协议数据格式
 * @param {Buffer} dataBuffer - 数据缓冲区
 * @returns {Object} 解析结果
 */
function parseMeterCoverEventRecord(dataBuffer) {
    const result = createStandardResult("开表盖事件记录", '301B0701', dataBuffer);

    try {
        // 根据698协议，开表盖事件记录是octet-string类型
        const { result: genericResult } = enhancedParseData(dataBuffer, '301B', '07');

        if (genericResult.dataType === '字节串') {
            // 直接返回原始数据，不进行假设性解析
            result.value = {
                rawData: genericResult.parsedValue,
                dataLength: genericResult.parsedValue.length / 2, // 十六进制字符串长度/2 = 字节数
                description: "开表盖事件记录原始数据"
            };

            setSuccessResult(result, [{
                type: "开表盖事件记录",
                rawData: genericResult.parsedValue,
                dataLength: genericResult.parsedValue.length / 2,
                unit: "字节",
                description: `电表开盖事件记录原始数据，长度 ${genericResult.parsedValue.length / 2} 字节`
            }], {
                unit: "字节",
                scale: 0,
                count: 1,
                generic: genericResult
            });

        } else if (genericResult.dataType === '数组') {
            // 如果是数组格式，返回数组中的原始数据
            if (genericResult.parsedValue && genericResult.parsedValue.length > 0) {
                const rawDataArray = [];
                for (const item of genericResult.parsedValue) {
                    if (item.dataType === '字节串') {
                        rawDataArray.push({
                            rawData: item.parsedValue,
                            dataLength: item.parsedValue.length / 2
                        });
                    }
                }
                
                result.value = {
                    rawDataArray: rawDataArray,
                    itemCount: rawDataArray.length,
                    description: "开表盖事件记录数组数据"
                };

                setSuccessResult(result, [{
                    type: "开表盖事件记录",
                    itemCount: rawDataArray.length,
                    rawDataArray: rawDataArray,
                    unit: "项",
                    description: `电表开盖事件记录数组，共 ${rawDataArray.length} 项`
                }], {
                    unit: "项",
                    scale: 0,
                    count: rawDataArray.length,
                    generic: genericResult
                });
            } else {
                throw new Error("数组为空，无法解析开盖事件记录");
            }
        } else if (genericResult.dataType === '结构体') {
            // 兼容部分设备以结构体返回：收集其中的字节串项，同时保留完整结构
            const struct = Array.isArray(genericResult.parsedValue) ? genericResult.parsedValue : [];
            const rawDataArray = [];
            for (let i = 0; i < struct.length; i++) {
                const it = struct[i] || {};
                if (it.dataType === '字节串' && typeof it.parsedValue === 'string') {
                    rawDataArray.push({ index: i, rawData: it.parsedValue, dataLength: it.parsedValue.length / 2 });
                }
            }

            result.value = {
                structureData: struct,
                elementCount: struct.length,
                rawDataArray: rawDataArray.length ? rawDataArray : undefined,
                itemCount: rawDataArray.length || undefined,
                description: "开表盖事件记录结构体数据"
            };

            setSuccessResult(result, [{
                type: "开表盖事件记录",
                elementCount: struct.length,
                rawDataArray: rawDataArray.length ? rawDataArray : undefined,
                unit: rawDataArray.length ? '项' : 'element',
                description: rawDataArray.length ? `结构体内含 ${rawDataArray.length} 段字节串` : `结构体，包含 ${struct.length} 个元素`
            }], {
                unit: rawDataArray.length ? '项' : undefined,
                scale: 0,
                count: rawDataArray.length || struct.length,
                generic: genericResult
            });
        } else {
            throw new Error(`开表盖事件记录数据格式不正确: ${genericResult.dataType}`);
        }

    } catch (e) {
        setErrorResult(result, e.message);
    }

    return result;
}


/**
 * 解析上一次开盖详细数据 - 基于实际698协议数据格式
 * @param {Buffer} dataBuffer - 数据缓冲区
 * @returns {Object} 解析结果
 */
function parseMeterCoverDetailData(dataBuffer) {
    const result = createStandardResult("上一次开盖详细数据", '301B0201', dataBuffer);

    try {
        // 根据698协议，开盖详细数据是结构体类型
        const { result: genericResult } = enhancedParseData(dataBuffer, '301B', '02');

        if (genericResult.dataType === '结构体' && Array.isArray(genericResult.parsedValue)) {
            // 直接返回结构体原始数据，不进行假设性解析
            result.value = {
                structureData: genericResult.parsedValue,
                elementCount: genericResult.parsedValue.length,
                description: "开盖详细数据结构体原始数据"
            };

            setSuccessResult(result, [{
                type: "上一次开盖详细数据",
                elementCount: genericResult.parsedValue.length,
                structureData: genericResult.parsedValue,
                unit: "项",
                description: `开盖详细数据结构体，包含 ${genericResult.parsedValue.length} 个元素`
            }], {
                unit: "项",
                scale: 0,
                count: genericResult.parsedValue.length,
                generic: genericResult
            });

        } else if (genericResult.dataType === '字节串') {
            // 如果是字节串格式，返回原始数据
            result.value = {
                rawData: genericResult.parsedValue,
                dataLength: genericResult.parsedValue.length / 2,
                description: "开盖详细数据原始字节串"
            };

            setSuccessResult(result, [{
                type: "上一次开盖详细数据",
                rawData: genericResult.parsedValue,
                dataLength: genericResult.parsedValue.length / 2,
                unit: "字节",
                description: `开盖详细数据原始字节串，长度 ${genericResult.parsedValue.length / 2} 字节`
            }], {
                unit: "字节",
                scale: 0,
                count: 1,
                generic: genericResult
            });

        } else {
            throw new Error(`上一次开盖详细数据格式不正确: ${genericResult.dataType}`);
        }

    } catch (e) {
        setErrorResult(result, e.message);
    }

    return result;
}

/**
 * 解析 上一次开盖事件记录 (301B-02-00) 的简化明细
 * 提取：事件序号、发生时间、结束时间；其余字段保留原始十六进制片段
 */
function parseLastOpenCoverRecord(payload) {
    const result = createStandardResult("上一次开盖事件记录", '301B0200', payload);
    try {
        const buf = Buffer.from(payload);

        // 尝试解析前置 RCSD 列描述块：N(1B) + N*(type(1)=0x00 + OAD(4B))
        let offset = 0;
        const columns = [];
        if (buf.length >= 6) {
            const n = buf[offset];
            let ok = true;
            let off = offset + 1;
            for (let i = 0; i < n; i++) {
                if (off + 5 > buf.length) { ok = false; break; }
                const csdType = buf[off++];
                const oiHi = buf[off++], oiLo = buf[off++];
                const att = buf[off++], idx = buf[off++];
                if (csdType !== 0x00) { ok = false; break; }
                const oadHex = `${oiHi.toString(16).padStart(2,'0')}${oiLo.toString(16).padStart(2,'0')}${att.toString(16).padStart(2,'0')}${idx.toString(16).padStart(2,'0')}`.toUpperCase();
                columns.push(oadHex);
            }
            if (ok && columns.length === n) {
                offset = off;
            } else {
                // 无法识别RCSD，降级为全文扫描
                columns.length = 0;
                offset = 0;
            }
        }

        // 如果识别出列，则按 A-ResultRecord: choice(1) + seqOf(1) + 按列逐项的 A-XDR 值 解析第一行
        let parsed = { sequence: null, startTime: null, endTime: null, extras: {} };
        if (columns.length > 0 && offset + 2 <= buf.length) {
            const choice = buf[offset++];
            if (choice === 0) {
                const dar = buf[offset] ?? 0xFF;
                throw new Error(`记录读取失败 DAR=0x${dar.toString(16)}`);
            }
            const rows = buf[offset++];
            // 仅取第一行
            const values = {};
            let off = offset;
            function parseValue(b) {
                const tag = b[0];
                switch (tag) {
                    case 0x06: // double-long-unsigned (4)
                        if (b.length < 5) return { consumed: 1, value: null };
                        return { consumed: 5, value: b.readUInt32BE(1) };
                    case 0x12: // long-unsigned (2)
                        if (b.length < 3) return { consumed: 1, value: null };
                        return { consumed: 3, value: b.readUInt16BE(1) };
                    case 0x11: // unsigned (1)
                        if (b.length < 2) return { consumed: 1, value: null };
                        return { consumed: 2, value: b[1] };
                    case 0x1C: // date-time-s (7)
                        if (b.length < 8) return { consumed: 1, value: null };
                        const y = b.readUInt16BE(1), m=b[3], d=b[4], h=b[5], mi=b[6], s=b[7];
                        const iso = `${y.toString().padStart(4,'0')}-${String(m).padStart(2,'0')}-${String(d).padStart(2,'0')} ${String(h).padStart(2,'0')}:${String(mi).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
                        return { consumed: 8, value: iso };
                    case 0x09: { // byte-string (len=AXDR)
                        if (b.length < 2) return { consumed: 1, value: null };
                        const L = readAxdrLength(b, 1);
                        const start = 1 + L.size, end = start + L.len;
                        if (end > b.length) return { consumed: b.length, value: null };
                        return { consumed: end, value: b.slice(start, end).toString('hex').toUpperCase() };
                    }
                    default:
                        // 不识别则原样透传十六进制，按最小 1 字节消费避免死循环
                        return { consumed: 1, value: null };
                }
            }
            for (let ci = 0; ci < columns.length; ci++) {
                if (off >= buf.length) break;
                const { consumed, value } = parseValue(buf.slice(off));
                values[columns[ci]] = value;
                off += consumed;
            }
            // 映射常用列
            parsed.sequence  = (values['20220200'] ?? values['20220000'] ?? null);
            parsed.startTime = values['201E0200'] ?? null;
            parsed.endTime   = values['20200200'] ?? null;
            parsed.extras = values;
        }

        // 若前置块无法解析，则降级：全文扫描两处时间与序号
        if (!parsed.startTime || !parsed.endTime) {
            const times = [];
            for (let i = 0; i + 8 <= buf.length; i++) {
                if (buf[i] === 0x1C) {
                    const t = buf.slice(i + 1, i + 8);
                    const year = (t[0] << 8) | t[1];
                    const mon = t[2], day = t[3], hh = t[4], mm = t[5], ss = t[6];
                    const iso = `${year.toString().padStart(4,'0')}-${String(mon).padStart(2,'0')}-${String(day).padStart(2,'0')} ${String(hh).padStart(2,'0')}:${String(mm).padStart(2,'0')}:${String(ss).toString().padStart(2,'0')}`;
                    times.push({ index: i, iso });
                    if (times.length >= 2) break;
                }
            }
            // 尝试在第一次时间前寻找 0x06 + 4B 作为事件序号
            if (times.length >= 1 && parsed.sequence == null) {
                for (let j = Math.max(0, times[0].index - 12); j + 5 <= buf.length && j < times[0].index; j++) {
                    if (buf[j] === 0x06 && (j + 5) <= times[0].index) { parsed.sequence = buf.readUInt32BE(j + 1); break; }
                }
            }
            if (!parsed.startTime && times[0]) parsed.startTime = times[0].iso;
            if (!parsed.endTime && times[1]) parsed.endTime = times[1].iso;
        }

        // 提取能量项：开盖前/后 正向/反向有功总电能（按现场记录列映射）
        // 约定：
        //  - 开盖"前"：OAD 00102201 (正向), 00202201 (反向)
        //  - 开盖"后"：OAD 00108201 (正向), 00208201 (反向)
        // 兼容部分设备 index 可能为 00：同样尝试 00102200/00202200/00108200/00208200
        const pick = (k) => (parsed.extras && Object.prototype.hasOwnProperty.call(parsed.extras, k)) ? parsed.extras[k] : undefined;
        // 兼容主/备列：0010/0020 为主，0050/0060 为补充列（部分设备写在 05 索引）
        const beforeFwdRaw = pick('00102201') ?? pick('00102200');
        const beforeRevRaw = pick('00202201') ?? pick('00202200') ?? pick('00702201');
        const afterFwdRaw  = pick('00108201') ?? pick('00108200') ?? pick('00502201');
        const afterRevRaw  = pick('00208201') ?? pick('00208200') ?? pick('00602201') ?? pick('00802201');

        // DL/T 698 电能量刻度：正/反向有功总电能按 0.01kWh（scale -2）
        const scaleEnergy = -2;
        const div = 100;
        const toNum = (v) => {
            const n = (typeof v === 'number') ? v
                : (typeof v === 'bigint') ? Number(v)
                : (typeof v === 'string' && /^\d+$/.test(v)) ? parseInt(v, 10)
                : null;
            // 过滤明显的无效占位（0xFFFFFFFF 等）
            if (n === null) return null;
            if (n === 0xFFFFFFFF || n === 0xFFFFFF || n === 0xFFFF) return null;
            return n;
        };
        const beforeFwd = toNum(beforeFwdRaw);
        const beforeRev = toNum(beforeRevRaw);
        const afterFwd  = toNum(afterFwdRaw);
        const afterRev  = toNum(afterRevRaw);

        // 输出
        result.value = {
            sequence: parsed.sequence ?? null,
            startTime: parsed.startTime ?? null,
            endTime: parsed.endTime ?? null,
            beforeForwardActive: (beforeFwd != null) ? beforeFwd / div : null,
            beforeReverseActive: (beforeRev != null) ? beforeRev / div : null,
            afterForwardActive:  (afterFwd  != null) ? afterFwd  / div : null,
            afterReverseActive:  (afterRev  != null) ? afterRev  / div : null,
            unit: 'kWh',
            scale: scaleEnergy,
            extras: parsed.extras
        };
        const detail = [];
        if (parsed.sequence != null) detail.push({ label: '事件序号', value: parsed.sequence });
        if (parsed.startTime) detail.push({ label: '发生时间', value: parsed.startTime });
        if (parsed.endTime) detail.push({ label: '结束时间', value: parsed.endTime });
        if (beforeFwd != null) detail.push({ label: '开盖前正向有功总电能', value: (beforeFwd / div).toFixed(Math.abs(scaleEnergy)), unit: 'kWh', rawValue: beforeFwd });
        if (beforeRev != null) detail.push({ label: '开盖前反向有功总电能', value: (beforeRev / div).toFixed(Math.abs(scaleEnergy)), unit: 'kWh', rawValue: beforeRev });
        if (afterFwd  != null) detail.push({ label: '开盖后正向有功总电能', value: (afterFwd  / div).toFixed(Math.abs(scaleEnergy)), unit: 'kWh', rawValue: afterFwd });
        if (afterRev  != null) detail.push({ label: '开盖后反向有功总电能', value: (afterRev  / div).toFixed(Math.abs(scaleEnergy)), unit: 'kWh', rawValue: afterRev });
        setSuccessResult(result, detail.length ? detail : [{ raw: buf.toString('hex').toUpperCase() }], { unit: 'kWh', scale: scaleEnergy, count: detail.length });
    } catch (e) {
        setErrorResult(result, e.message);
    }
    return result;
}

/**
 * 解析电池电压数据 - 时钟电池电压和抄表电池电压
 * @param {Buffer} dataBuffer - 数据缓冲区
 * @param {string} oad - OAD标识
 * @returns {Object} 解析结果
 */
function parseBatteryVoltage(dataBuffer, oad) {
    const oadInfo = getOADInfo(oad);
    const result = createStandardResult(oadInfo ? oadInfo.desc : "电池电压", oad, dataBuffer);

    try {
        // 根据698协议，电池电压是double-long-unsigned类型
        const { result: genericResult } = enhancedParseData(dataBuffer, oad.slice(0, 4), oad.slice(4, 6));

        // 兼容：双长无符号整数 或 数组包裹的单值
        let rawVoltage = null;
        if (genericResult.dataType === '双长无符号整数' && typeof genericResult.parsedValue === 'number') {
            rawVoltage = genericResult.parsedValue;
        } else if (genericResult.dataType === '数组' && Array.isArray(genericResult.parsedValue) && genericResult.parsedValue.length > 0) {
            const first = genericResult.parsedValue[0];
            if (first && typeof first.parsedValue === 'number') rawVoltage = first.parsedValue;
        } else if (typeof genericResult.parsedValue === 'number') {
            rawVoltage = genericResult.parsedValue;
        }

        if (rawVoltage === null) {
            throw new Error(`电池电压数据格式不正确: ${genericResult.dataType}`);
        }

        const voltageV = rawVoltage / 100; // -2 scale
        result.value = {
            rawValue: rawVoltage,
            voltage: voltageV,
            unit: "V",
            description: `${oadInfo ? oadInfo.desc : "电池电压"}: ${voltageV.toFixed(2)}V`
        };

        setSuccessResult(result, [{
            type: oadInfo ? oadInfo.desc : "电池电压",
            rawValue: rawVoltage,
            voltage: voltageV,
            unit: "V",
            description: `${oadInfo ? oadInfo.desc : "电池电压"} ${voltageV.toFixed(2)}V`
        }], {
            unit: "V",
            scale: -2,
            count: 1,
            generic: genericResult
        });

    } catch (e) {
        setErrorResult(result, e.message);
    }

    return result;
}

function parseEnergyData(dataBuffer, oad) {
    const result = createStandardResult("电能数据", oad, dataBuffer);
    try {
        const { result: genericResult } = enhancedParseData(dataBuffer, oad.slice(0, 4), oad.slice(4, 6));
        const isExt = oad.endsWith('0400');
        const scale = isExt ? -4 : -2;
        const divisor = Math.pow(10, Math.abs(scale));

        if (typeof genericResult.parsedValue === 'number' || typeof genericResult.parsedValue === 'bigint') {
            const valueStr = (Number(genericResult.parsedValue) / divisor).toFixed(Math.abs(scale));
            result.value = parseFloat(valueStr);
            setSuccessResult(result, [{ label: "电能量", value: valueStr, unit: "kWh", rawValue: genericResult.parsedValue.toString(), scale }],
                { unit: "kWh", scale, count: 1, generic: genericResult });
        } else if (genericResult.dataType === '数组') {
            const labels = ["总", "尖", "峰", "平", "谷"];
            const values = genericResult.parsedValue.map((item, index) => {
                const raw = Number(item.parsedValue);
                return {
                    label: labels[index] || `费率${index + 1}`,
                    value: (raw / divisor).toFixed(Math.abs(scale)),
                    unit: "kWh", rawValue: raw, scale
                };
            });
            result.value = values.map(i => parseFloat(i.value));
            setSuccessResult(result, values, { unit: "kWh", scale, count: values.length, generic: genericResult });
        } else { throw new Error(`电能数据格式不正确: ${genericResult.dataType}`); }
    } catch (e) { setErrorResult(result, e.message); }
    return result;
}

function parseDemandData(dataBuffer, oad) {
    const result = createStandardResult("需量数据", oad, dataBuffer);
    try {
        const { result: genericResult } = enhancedParseData(dataBuffer, oad.slice(0, 4), oad.slice(4, 6));
        const scale = -4;
        const divisor = Math.pow(10, Math.abs(scale));

        if (typeof genericResult.parsedValue === 'number' || typeof genericResult.parsedValue === 'bigint') {
            const valueStr = (Number(genericResult.parsedValue) / divisor).toFixed(Math.abs(scale));
            result.value = parseFloat(valueStr);
            setSuccessResult(result, [{ label: "最大需量", value: valueStr, unit: "kW", rawValue: genericResult.parsedValue.toString(), scale }],
                { unit: "kW", scale, count: 1, generic: genericResult });
        } else if (genericResult.dataType === '数组') {
            const labels = ["总最大需量", "费率1", "费率2", "费率3", "费率4"];
            const values = genericResult.parsedValue.map((item, index) => {
                const raw = Number(item.parsedValue);
                return {
                    label: labels[index] || `费率${index + 1}`,
                    value: (raw / divisor).toFixed(Math.abs(scale)),
                    unit: "kW", rawValue: raw, scale
                };
            });
            result.value = values.map(i => parseFloat(i.value));
            setSuccessResult(result, values, { unit: "kW", scale, count: values.length, generic: genericResult });
        } else { throw new Error(`需量数据格式不正确: ${genericResult.dataType}`); }
    } catch (e) { setErrorResult(result, e.message); }
    return result;
}

function parseVoltageCurrentData(dataBuffer, oad) {
    const result = createStandardResult("电压电流测量数据", oad, dataBuffer);
    try {
        const isVoltage = oad.startsWith("2000");
        const unit = isVoltage ? "V" : "A";
        const scale = isVoltage ? -1 : -3;
        const { result: genericResult } = enhancedParseData(dataBuffer, oad.slice(0, 4), oad.slice(4, 6));
        const divisor = Math.pow(10, Math.abs(scale));

        if (genericResult.dataType === '数组') {
            const phases = ["A相", "B相", "C相"];
            const measurements = genericResult.parsedValue.map((item, i) => {
                const raw = Number(item.parsedValue);
                return {
                    phase: phases[i] || `相${i + 1}`,
                    value: (raw / divisor).toFixed(Math.abs(scale)),
                    unit, rawValue: raw, scale
                };
            });
            result.value = measurements.map(i => parseFloat(i.value));
            setSuccessResult(result, measurements, { unit, scale, count: measurements.length, generic: genericResult });
        } else if (typeof genericResult.parsedValue === 'number') {
            const raw = Number(genericResult.parsedValue);
            const valueStr = (raw / divisor).toFixed(Math.abs(scale));
            result.value = parseFloat(valueStr);
            setSuccessResult(result, [{ phase: "单相", value: valueStr, unit, rawValue: raw, scale }],
                { unit, scale, count: 1, generic: genericResult });
        } else { throw new Error(`测量数据格式不正确: ${genericResult.dataType}`); }
    } catch (e) { setErrorResult(result, e.message); }
    return result;
}

// 瞬时功率数据解析（2004 有功功率 W、2005 无功功率 var；通常为 总/A/B/C 四个值，double-long，scale -1）
function parseInstantPowerData(dataBuffer, oad) {
    const isActive = oad.startsWith('2004');
    const desc = isActive ? '有功功率' : '无功功率';
    const unit = isActive ? 'W' : 'var';
    const scale = -1; // 原始值/10
    const result = createStandardResult(desc, oad, dataBuffer);
    try {
        const { result: genericResult } = enhancedParseData(dataBuffer, oad.slice(0, 4), oad.slice(4, 6));
        const divisor = Math.pow(10, Math.abs(scale));

        if (genericResult.dataType === '数组') {
            const labels = ['总', 'A相', 'B相', 'C相'];
            const values = genericResult.parsedValue.map((item, i) => {
                const raw = Number(item.parsedValue || 0);
                return {
                    label: `${labels[i] || `项${i+1}`}${desc}`,
                    value: (raw / divisor).toFixed(Math.abs(scale)),
                    unit,
                    rawValue: raw,
                    scale
                };
            });
            result.value = values.map(v => parseFloat(v.value));
            setSuccessResult(result, values, { unit, scale, count: values.length, generic: genericResult });
        } else if (typeof genericResult.parsedValue === 'number' || typeof genericResult.parsedValue === 'bigint') {
            const raw = Number(genericResult.parsedValue);
            const valueStr = (raw / divisor).toFixed(Math.abs(scale));
            result.value = parseFloat(valueStr);
            setSuccessResult(result, [{ label: desc, value: valueStr, unit, rawValue: raw, scale }], { unit, scale, count: 1, generic: genericResult });
        } else {
            throw new Error(`功率数据格式不正确: ${genericResult.dataType}`);
        }
    } catch (e) {
        setErrorResult(result, e.message);
    }
    return result;
}

/**
 * 解析脉冲常数数据 - 基于C#代码中的698协议解析逻辑
 * @param {Buffer} dataBuffer - 数据缓冲区
 * @param {string} oad - OAD标识符
 * @returns {Object} 解析结果
 */
function parsePulseConstantData(dataBuffer, oad) {
    const result = createStandardResult("脉冲常数", oad, dataBuffer);

    try {
        // 根据C#代码中的解析逻辑，脉冲常数是双长无符号整数类型
        const { result: genericResult } = enhancedParseData(dataBuffer, oad.slice(0, 4), oad.slice(4, 6));

        // 确定常数类型和单位
        const isActive = oad === '41090200';
        const constantType = isActive ? '脉冲有功常数' : '脉冲无功常数';
        const unit = isActive ? '脉冲/kWh' : '脉冲/kvarh';

        if (genericResult.dataType === '双长无符号整数') {
            // 直接使用enhancedParseData已经正确解析的值
            const pulseConstant = Number(genericResult.parsedValue);
            result.value = pulseConstant;

            setSuccessResult(result, [{
                type: constantType,
                constant: pulseConstant,
                unit: unit,
                rawValue: pulseConstant,
                description: `电表${constantType}为 ${pulseConstant} ${unit}`
            }], {
                unit: unit,
                scale: 0,
                count: 1,
                generic: genericResult
            });

        } else if (genericResult.dataType === '数组') {
            // 如果是数组格式，取第一个元素
            if (genericResult.parsedValue && genericResult.parsedValue.length > 0) {
                const firstItem = genericResult.parsedValue[0];
                if (firstItem.dataType === '双长无符号整数') {
                    // 直接使用enhancedParseData已经正确解析的值
                    const pulseConstant = Number(firstItem.parsedValue);
                    result.value = pulseConstant;

                    setSuccessResult(result, [{
                        type: constantType,
                        constant: pulseConstant,
                        unit: unit,
                        rawValue: pulseConstant,
                        description: `电表${constantType}为 ${pulseConstant} ${unit}`
                    }], {
                        unit: unit,
                        scale: 0,
                        count: 1,
                        generic: genericResult
                    });
                } else {
                    throw new Error(`数组中的数据类型不正确: ${firstItem.dataType}`);
                }
            } else {
                throw new Error("数组为空，无法解析脉冲常数");
            }
        } else {
            throw new Error(`脉冲常数数据格式不正确: ${genericResult.dataType}`);
        }

    } catch (e) {
        setErrorResult(result, e.message);
    }

    return result;
}

// 日/结算日冻结专用解析（兼容 00+OAD 和 直接OAD 两种）
function parseFreezeDaily(payload, oad/* 50040200 | 50050200 */) {
    const result = createStandardResult("冻结数据", oad, payload);
    try {
        let offset = 0;
        let energyOAD = null;

        // 情况A：00 + OAD
        if (payload.length >= 5 && payload[0] === 0x00) {
            const maybe = payload.slice(1, 5).toString('hex').toUpperCase();
            if (/^[0-9A-F]{8}$/.test(maybe)) {
                energyOAD = maybe; offset = 5;
            } else {
                offset = 1; // 兼容占位但非OAD
            }
            // 情况B：直接 OAD 起
        } else if (payload.length >= 4) {
            const maybe = payload.slice(0, 4).toString('hex').toUpperCase();
            if (/^[0-9A-F]{8}$/.test(maybe)) {
                energyOAD = maybe; offset = 4;
            }
        }

        const { result: parsed } = enhancedParseData(payload.slice(offset), (energyOAD || '').slice(0, 4), (energyOAD || '').slice(4, 6));

        // 将"数组套数组"拍平为 5 项（总/尖/峰/平/谷）
        let values = [];
        if (parsed.dataType === '数组' && Array.isArray(parsed.parsedValue)) {
            if (parsed.parsedValue.length === 1 && parsed.parsedValue[0].dataType === '数组') {
                values = parsed.parsedValue[0].parsedValue.map(it => Number(it.parsedValue));
            } else {
                values = parsed.parsedValue.map(it => Number(it.parsedValue));
            }
        } else if (typeof parsed.parsedValue === 'number') {
            values = [Number(parsed.parsedValue)];
        } else {
            const generic = createStandardResult("冻结数据(通用)", oad, payload.slice(offset));
            generic.value = parsed.parsedValue;
            setSuccessResult(generic, parsed, { generic: parsed });
            return generic;
        }

        const scale = (energyOAD && energyOAD.endsWith('0400')) ? -4 : -2;
        const { valueArray, detailed } = formatFreezeValues(values, { scale, unit: 'kWh' });

        result.value = valueArray;
        setSuccessResult(result, detailed, {
            unit: 'kWh', scale, count: detailed.length,
            generic: parsed
        });
        result.metadata.energyOAD = energyOAD || 'UNKNOWN';
        return result;

    } catch (e) {
        setErrorResult(result, e.message);
        return result;
    }
}

/**
 * 解析自动轮显参数OAD F3000500
 * 基于用户提供的帧结构分析：
 * 68 24 00 C3 05 90 19 11 00 30 04 11 0C DB 90 00 0B 87 01 01 F3 00 05 00 14 00 00 00 01 00 04 BA 28 8F 9C E7 4F 16
 * 
 * @param {Buffer} payload - 数据载荷
 * @returns {Object} 解析结果
 */
function parseAutoDisplayParameters(payload) {
    const result = createStandardResult("自动轮显参数", 'F3000500', payload);

    try {
        if (!payload || payload.length === 0) {
            throw new Error("轮显参数数据为空");
        }

        // 基于用户分析的帧结构，解析SET-Response数据
        const parsedData = parseSetResponseData(payload);

        // 设置成功结果
        result.value = parsedData;
        setSuccessResult(result, parsedData, {
            count: 1,
            generic: {
                dataType: '自动轮显参数SET响应',
                parsedValue: parsedData
            }
        });

    } catch (e) {
        setErrorResult(result, e.message);
    }

    return result;
}

/**
 * 解析SET-Response数据（基于用户提供的帧结构分析）
 * @param {Buffer} payload - SET响应数据载荷
 * @returns {Object} 解析结果
 */
function parseSetResponseData(payload) {
    const result = {
        type: 'SET-Response数据',
        rawData: payload.toString('hex').toUpperCase(),
        length: payload.length,
        analysis: []
    };

    try {
        let offset = 0;

        // 根据用户分析，这是SetResponseNormalList结构
        // 字节16: 0x87 (SET子类型)
        // 字节17: 0x01 (PIID - 服务序号1)
        // 字节18-21: F3 00 05 00 (OAD - 自动轮显参数)
        // 字节22: 0x14 (结果数组长度 - 1条结果)
        // 字节23-24: 00 00 (结果码 - 成功)
        // 字节25-27: 01 00 04 (时间标签 - 无，固定0)

        if (payload.length >= 8) {
            // 解析PIID
            const piid = payload[offset++];
            result.piid = {
                value: piid,
                hex: '0x' + piid.toString(16).padStart(2, '0').toUpperCase(),
                description: '服务序号'
            };

            // 解析OAD
            const oad = payload.slice(offset, offset + 4).toString('hex').toUpperCase();
            offset += 4;
            result.oad = {
                value: oad,
                description: '自动轮显参数（显示类对象17，属性5）'
            };

            // 解析结果数组长度
            const resultArrayLength = payload[offset++];
            result.resultArrayLength = {
                value: resultArrayLength,
                hex: '0x' + resultArrayLength.toString(16).padStart(2, '0').toUpperCase(),
                description: '结果数组长度'
            };

            // 解析结果码
            if (offset + 1 < payload.length) {
                const resultCode = payload.readUInt16LE(offset);
                offset += 2;
                result.resultCode = {
                    value: resultCode,
                    hex: '0x' + resultCode.toString(16).padStart(4, '0').toUpperCase(),
                    description: resultCode === 0x0000 ? '成功' : '失败',
                    success: resultCode === 0x0000
                };
            }

            // 解析时间标签
            if (offset + 2 < payload.length) {
                const timeTag = payload.slice(offset, offset + 3);
                offset += 3;
                result.timeTag = {
                    value: timeTag.toString('hex').toUpperCase(),
                    description: '时间标签（固定0，无实际时间）',
                    raw: Array.from(timeTag).map(b => '0x' + b.toString(16).padStart(2, '0').toUpperCase())
                };
            }

            // 解析剩余数据（如果有）
            if (offset < payload.length) {
                const remainingData = payload.slice(offset);
                result.remainingData = {
                    hex: remainingData.toString('hex').toUpperCase(),
                    length: remainingData.length,
                    bytes: Array.from(remainingData).map(b => '0x' + b.toString(16).padStart(2, '0').toUpperCase())
                };
            }
        }

        // 生成摘要
        result.summary = `自动轮显参数设置${result.resultCode?.success ? '成功' : '失败'}，PIID=${result.piid?.hex}，OAD=${result.oad?.value}`;

    } catch (error) {
        result.error = error.message;
    }

    return result;
}


/**
 * 解析 40070205 液晶显示电能小数位数属性 a
 * 期望返回一个 0~8 的整数（不同厂家可能稍有差异）
 * 兼容：long-unsigned(0x12,2B)、double-long-unsigned(0x06,4B)、array 包裹、以及单字节可见/字节串
 */
function parseLCDDecimalDigits(dataBuffer) {
    const oad = '40070205';
    const result = createStandardResult("液晶小数位数属性a", oad, dataBuffer);

    try {
        // 快速路径：0x11 = unsigned(1B)，紧随1字节即为 a
        if (dataBuffer && dataBuffer.length >= 2 && dataBuffer[0] === 0x11) {
            const a = dataBuffer[1];
            result.value = a;
            setSuccessResult(result, [{ label: 'a(小数位数)', value: a, unit: 'digit' }], {
                unit: 'digit', scale: 0, count: 1,
                generic: { dataType: '无符号整数', parsedValue: a }
            });
            return result;
        }
        // 先用通用解析器粗解，拿到结构与类型
        const { result: generic } = enhancedParseData(dataBuffer, oad.slice(0, 4), oad.slice(4, 6));

        // 抽取数值的小工具（容错）
        const pickInt = (v) => {
            if (v === null || v === undefined) return null;
            if (typeof v === 'number') return v;
            if (typeof v === 'bigint') return Number(v);
            if (typeof v === 'string') {
                // 可能是 HEX 或十进制字符串
                if (/^[0-9]+$/.test(v)) return parseInt(v, 10);
                if (/^[0-9A-F]+$/i.test(v) && v.length <= 2) return parseInt(v, 16);
            }
            return null;
        };

        let a = null;

        if (generic.dataType === '长无符号整数' || generic.dataType === '双长无符号整数') {
            a = pickInt(generic.parsedValue);
        } else if (generic.dataType === '数组' && Array.isArray(generic.parsedValue) && generic.parsedValue.length > 0) {
            // 兼容：有的设备会用 array(1) 包一层
            const first = generic.parsedValue[0];
            a = pickInt(first?.parsedValue);
        } else if (generic.dataType === '字节串' || generic.dataType === '可见字符串') {
            // 兜底：某些设备会用 1 字节/可见字符直接表示
            a = pickInt(generic.parsedValue);
            if (a === null && typeof generic.parsedValue === 'string' && generic.parsedValue.length >= 2) {
                a = parseInt(generic.parsedValue.slice(0, 2), 16);
            }
        }

        if (a === null || isNaN(a)) {
            throw new Error(`无法识别的小数位返回格式: ${generic.dataType}`);
        }

        // 一般 0~8 合理，超界给个温和提示但仍返回
        const hint = (a < 0 || a > 12) ? `（异常范围，值=${a}）` : '';
        result.value = a;
        setSuccessResult(result, [{ label: 'a(小数位数)', value: a, unit: 'digit' }], {
            unit: 'digit',
            scale: 0,
            count: 1,
            generic,
        });
        if (hint) result.hint = hint;

    } catch (e) {
        setErrorResult(result, e.message);
    }

    return result;
}






/** ---- APDU 解析路由 ---- */

function oadParserRouter(payload, oad) {
    const prefix = oad.slice(0, 4);
    if (oad === '50040200' || oad === '50050200') return parseFreezeDaily(payload, oad);
    if (['0000', '0010', '0020', '0011', '0012', '0013', '0021', '0022', '0023'].includes(prefix)) return parseEnergyData(payload, oad);
    if (['1010', '1020', '1011', '1012', '1013', '1021', '1022', '1023'].includes(prefix)) return parseDemandData(payload, oad);
    if (['2000', '2001'].includes(prefix)) return parseVoltageCurrentData(payload, oad);
    if (['2004', '2005'].includes(prefix)) return parseInstantPowerData(payload, oad);
    // 30110700：掉电事件-当前记录数（对齐C#侧逻辑，读取当前记录条数）
    if (oad === '30110700') return parsePowerFailureEventCount(payload);
    if (oad === '301B0400') return parseMeterCoverEvent(payload); // 开表盖总次数
    if (oad === '301B0701') return parseMeterCoverEventRecord(payload); // 开表盖事件记录
    if (oad === '301B0201') return parseMeterCoverDetailData(payload); // 上一次开盖详细数据
    if (oad === '301B0200') return parseLastOpenCoverRecord(payload);   // 上一次开盖事件记录（RecordRow）
    if (oad === '302C0701') return parsePowerAbnormalCount(payload); // 电源异常事件总次数
    if (oad === '20140200' || oad === '20140201') return parseMeterStatus(payload, oad);
    if (oad === '20140202') return parseMeterStatusWord2(payload);
    if (oad === '20140203') return parseMeterStatusWord3(payload);
    if (oad === 'F3000500') return parseAutoDisplayParameters(payload); // 自动轮显参数
    if (oad === '41090200' || oad === '410A0200') return parsePulseConstantData(payload, oad); // 脉冲常数
    if (oad === '40070205') return parseLCDDecimalDigits(payload); //抄读当前组合有功电能数据块
    if (oad === '20110200') return parseBatteryVoltage(payload, oad); // 时钟电池电压
    if (oad === '20120200') return parseBatteryVoltage(payload, oad); // 停电抄表电池电压
    // 通用兜底
    const oadInfo = getOADInfo(oad) || { desc: "通用数据" };
    const genericStdResult = createStandardResult(oadInfo.desc, oad, payload);
    try {
        const { result: genericResult } = enhancedParseData(payload, oad.slice(0, 4), oad.slice(4, 6));
        genericStdResult.value = genericResult.parsedValue;
        setSuccessResult(genericStdResult, genericResult, { generic: genericResult });
    } catch (e) {
        setErrorResult(genericStdResult, e.message);
    }
    return genericStdResult;
}

function normalizeGetResponseType(typeByte) {
    if (typeByte === undefined) return { raw: typeByte, normalized: null };
    const info = { raw: typeByte, normalized: null };
    if ([1, 2, 3].includes(typeByte)) {
        info.normalized = typeByte;
        return info;
    }
    const normalized = typeByte & 0x1F;
    if ([1, 2, 3].includes(normalized)) {
        info.normalized = normalized;
        info.flags = {
            tagClass: (typeByte & 0xC0) >> 6,
            constructed: !!(typeByte & 0x20)
        };
    }
    return info;
}

function consumeGetResultChoice(apduBuffer, offset) {
    if (offset >= apduBuffer.length) {
        return { status: "ok", dataOffset: offset, explicitChoice: null };
    }
    const choice = apduBuffer[offset];
    if (choice === 0) {
        const dar = apduBuffer[offset + 1] ?? 0xFF;
        return {
            status: "failed",
            dataOffset: Math.min(apduBuffer.length, offset + 2),
            dar
        };
    }
    if (choice === 1) {
        return {
            status: "ok",
            dataOffset: offset + 1,
            explicitChoice: 1
        };
    }
    return {
        status: "ok",
        dataOffset: offset,
        explicitChoice: null
    };
}

function parseGetResponse(apduBuffer, result) {
    let offset = 1;

    const responseTypeByte = apduBuffer[offset++];
    if (responseTypeByte === undefined) {
        result.unifiedFormat.error = "GET-Response缺少类型标志";
        return;
    }

    const typeInfo = normalizeGetResponseType(responseTypeByte);
    result.unifiedFormat.responseTypeRaw = `0x${responseTypeByte.toString(16).toUpperCase()}`;
    if (typeInfo.flags) result.unifiedFormat.responseTypeFlags = typeInfo.flags;

    const responseType = typeInfo.normalized;
    if (![1, 2, 3].includes(responseType)) {
        result.unifiedFormat.error = `不支持的GET-Response类型: 0x${responseTypeByte.toString(16).toUpperCase()}`;
        return;
    }
    result.unifiedFormat.responseType = responseType;

    result.unifiedFormat.invokeId = apduBuffer[offset++] ?? 0;

    if (responseType === 2) {
        try {
            const listInfo = parseGetResponseListEntries(apduBuffer, offset);
            result.unifiedFormat.type = "GET-Response-List";
            result.unifiedFormat.status = "成功";
            result.unifiedFormat.entries = listInfo.entries;
            result.unifiedFormat.count = listInfo.count;
        } catch (err) {
            result.unifiedFormat.status = "失败";
            result.unifiedFormat.error = `GET-Response-List 解析失败: ${err.message}`;
        }
        return;
    }

    const oadSlice = apduBuffer.slice(offset, offset + 4);
    if (oadSlice.length < 4) {
        result.unifiedFormat.error = "GET-Response缺少OAD字段";
        return;
    }
    const oad = oadSlice.toString('hex').toUpperCase();
    offset += 4;

    result.unifiedFormat.oad = oad;
    result.unifiedFormat.objectInfo = getOADInfo(oad) || { desc: "未知对象" };

    const choiceOutcome = consumeGetResultChoice(apduBuffer, offset);
    if (choiceOutcome.explicitChoice !== null) {
        result.unifiedFormat.dataChoice = choiceOutcome.explicitChoice;
    }
    if (choiceOutcome.status === "failed") {
        result.unifiedFormat.status = "失败";
        result.unifiedFormat.error = getDarDescription(choiceOutcome.dar);
        return;
    }

    const dataBuffer = apduBuffer.slice(choiceOutcome.dataOffset);
    result.unifiedFormat.status = "成功";

    if (responseType === 1) {
        result.unifiedFormat.data = oadParserRouter(dataBuffer, oad);
        return;
    }

    result.unifiedFormat.type = "GET-Response-Record";

    // 针对日/结算日冻结 OAD（50040200/50050200）做特殊解析，设备返回为记录型自定义结构
    if (oad === '50040200' || oad === '50050200') {
        result.unifiedFormat.data = parseDailyFreezeRecord(dataBuffer, oad);
        return;
    }

    // Record 类型优先走专用解析（开盖事件等），否则兜底通用解析
    if (oad === '301B0200') { // 上一次开盖事件记录
        result.unifiedFormat.data = parseLastOpenCoverRecord(dataBuffer);
        return;
    }

    const oadInfo = getOADInfo(oad) || { desc: "记录/列表数据" };
    const stdResult = createStandardResult(oadInfo.desc, oad, dataBuffer);
    try {
        const { result: parsedData } = enhancedParseData(dataBuffer, oad.slice(0, 4), oad.slice(4, 6));
        stdResult.value = parsedData.parsedValue;
        setSuccessResult(stdResult, parsedData, { generic: parsedData });
    } catch (e) {
        setErrorResult(stdResult, e.message);
    }
    result.unifiedFormat.data = stdResult;
}

function parseConnectResponse(apduBuffer, result) {
    try {
        let offset = 1;
        result.unifiedFormat.invokeId = apduBuffer[offset++] ?? 0;

        const readField = (len) => {
            if (offset + len > apduBuffer.length) throw new Error("CONNECT-Response 长度不足");
            const slice = apduBuffer.slice(offset, offset + len);
            offset += len;
            return slice.toString('hex').toUpperCase();
        };

        const readUInt = (len) => {
            const slice = readField(len);
            return parseInt(slice, 16);
        };

        const factoryInfo = {
            factoryCode: readField(4),
            softwareVersion: readField(4),
            softwareDate: readField(6),
            hardwareVersion: readField(4),
            hardwareDate: readField(6),
            additionInfo: readField(8)
        };

        const appVersion = readField(2);
        const protocolConformance = readField(8);
        const functionConformance = readField(16);
        const serverSendSize = readUInt(2);
        const serverRecvSize = readUInt(2);
        const serverRecvMaxWindow = readUInt(1);
        const serverDealMaxApdu = readUInt(2);
        const expectConnectTimeout = readUInt(4);

        const remainder = apduBuffer.slice(offset);
        let connectionResult = null;
        let authAddInfoFlag = null;
        let securityData = null;
        let followReport = null;
        let timeTagFlag = null;
        let trailingHex = null;

        let cursor = 0;
        const ensure = (len) => {
            if (cursor + len > remainder.length) throw new Error("CONNECT-Response 结构体残缺");
        };
        const takeByte = () => {
            ensure(1);
            return remainder[cursor++];
        };
        const takeLengthValueHex = () => {
            ensure(1);
            const len = remainder[cursor++];
            ensure(len);
            const slice = remainder.slice(cursor, cursor + len);
            cursor += len;
            return { len, hex: slice.toString('hex').toUpperCase() };
        };

        if (remainder.length) {
            connectionResult = takeByte();
            if (cursor < remainder.length) {
                authAddInfoFlag = takeByte();
                if (authAddInfoFlag === 0x01) {
                    const serverRn = takeLengthValueHex();
                    const serverSignature = takeLengthValueHex();
                    securityData = {
                        serverRnLen: serverRn.len,
                        serverRnHex: serverRn.hex,
                        serverSignatureLen: serverSignature.len,
                        serverSignatureHex: serverSignature.hex
                    };
                }
                if (cursor < remainder.length) {
                    followReport = takeByte();
                }
                if (cursor < remainder.length) {
                    timeTagFlag = takeByte();
                    if (timeTagFlag === 0x01 && cursor < remainder.length) {
                        const timeTagLen = Math.min(7, remainder.length - cursor);
                        const timeTagBytes = remainder.slice(cursor, cursor + timeTagLen);
                        cursor += timeTagLen;
                        result.unifiedFormat.timeTagRaw = timeTagBytes.toString('hex').toUpperCase();
                    }
                }
                if (cursor < remainder.length) {
                    trailingHex = remainder.slice(cursor).toString('hex').toUpperCase();
                }
            }
        }

        result.unifiedFormat.factoryInfo = factoryInfo;
        result.unifiedFormat.appVersion = appVersion;
        result.unifiedFormat.protocolConformance = protocolConformance;
        result.unifiedFormat.functionConformance = functionConformance;
        result.unifiedFormat.serverSendSize = serverSendSize;
        result.unifiedFormat.serverRecvSize = serverRecvSize;
        result.unifiedFormat.serverRecvMaxWindow = serverRecvMaxWindow;
        result.unifiedFormat.serverDealMaxApdu = serverDealMaxApdu;
        result.unifiedFormat.expectConnectTimeout = expectConnectTimeout;
        result.unifiedFormat.connectionResult = connectionResult;
        result.unifiedFormat.authAddInfoFlag = authAddInfoFlag;
        if (securityData) result.unifiedFormat.securityData = securityData;
        result.unifiedFormat.followReport = followReport;
        result.unifiedFormat.timeTagFlag = timeTagFlag;
        if (trailingHex) result.unifiedFormat.trailingHex = trailingHex;
    } catch (err) {
        result.unifiedFormat.error = `CONNECT-Response 解析失败: ${err.message}`;
    }
}

function parseGetResponseListEntries(buffer, offset) {
    if (offset >= buffer.length) throw new Error("缺少列表元素个数");
    const count = buffer[offset++];
    const entries = [];
    let cursor = offset;

    for (let i = 0; i < count; i++) {
        if (cursor + 4 > buffer.length) throw new Error("GET-Response-List 数据长度不足（OAD缺失）");
        const oad = buffer.slice(cursor, cursor + 4).toString('hex').toUpperCase();
        cursor += 4;

        const choiceOutcome = consumeGetResultChoice(buffer, cursor);
        if (choiceOutcome.status === "failed") {
            entries.push({
                oad,
                status: "失败",
                error: getDarDescription(choiceOutcome.dar)
            });
            cursor = choiceOutcome.dataOffset;
            continue;
        }

        const dataBuffer = buffer.slice(choiceOutcome.dataOffset);
        let consumed = dataBuffer.length;
        try {
            const { consumed: len } = enhancedParseData(dataBuffer, oad.slice(0, 4), oad.slice(4, 6));
            consumed = len;
        } catch (_) {
            // ignore, fallback to entire buffer remainder
        }
        const rawChunk = dataBuffer.slice(0, consumed);
        const parsed = oadParserRouter(rawChunk, oad);
        entries.push({
            oad,
            status: "成功",
            data: parsed
        });
        cursor = choiceOutcome.dataOffset + consumed;
    }

    return { count, entries, nextOffset: cursor };
}

// 查找嵌套 APDU 起点（支持 0x85/0x90）
function parseSecurityResponse(apduBuffer, result) {
    let offset = 1;
    const securityDataType = apduBuffer[offset++] ?? 0;
    result.unifiedFormat.type = "SECURITY-Response";
    result.unifiedFormat.securityDataType = securityDataType;

    if (securityDataType === 0) {
        // 明文：直接当作嵌套 APDU 处理
        const { len, size } = readAxdrLength(apduBuffer, offset);
        offset += size;
        const end = offset + len;
        if (end > apduBuffer.length) {
            result.unifiedFormat.error = "Security-Response 明文长度越界";
            result.unifiedFormat.rawData = apduBuffer.slice(offset).toString('hex').toUpperCase();
            return;
        }
        const nested = apduBuffer.slice(offset, end);
        const nestedResult = enhancedParseApdu(nested);
        result.unifiedFormat = nestedResult.unifiedFormat;
        result.unifiedFormat.type = "SECURITY-Response";
        result.unifiedFormat.securityDataType = securityDataType;
        result.unifiedFormat.wrapper = { type: "Security-Response", securityDataType: 0 };
        return;
    }

    try {
        let cipherSeg = null;
        let securityErrorText = null;
        if (securityDataType === 2) {
            if (offset < apduBuffer.length) {
                result.unifiedFormat.securityErrorCode = apduBuffer[offset++];
                securityErrorText = getDarDescription(result.unifiedFormat.securityErrorCode);
                if (securityErrorText) result.unifiedFormat.securityErrorText = securityErrorText;
            }
        } else if (offset < apduBuffer.length) {
            cipherSeg = readAxdrSegment(apduBuffer, offset);
            offset = cipherSeg.nextOffset;
            if (cipherSeg.hex != null) result.unifiedFormat.cipherHex = cipherSeg.hex;
        }

        let macPresent = null;
        let macChoice = null;
        let macHex = null;
        if (offset < apduBuffer.length) {
            macPresent = apduBuffer[offset++];
            if (macPresent && offset < apduBuffer.length) {
                macChoice = apduBuffer[offset++];
                if (offset < apduBuffer.length) {
                    const macSeg = readAxdrSegment(apduBuffer, offset);
                    macHex = macSeg.hex;
                    offset = macSeg.nextOffset;
                }
            }
        }

        result.unifiedFormat.macPresent = macPresent;
        if (macChoice != null) result.unifiedFormat.macChoice = macChoice;
        if (macHex) result.unifiedFormat.macHex = macHex;
        if (offset < apduBuffer.length) result.unifiedFormat.trailingHex = apduBuffer.slice(offset).toString('hex').toUpperCase();

        // 若密文中嵌套 APDU，尽量解析
        if (cipherSeg && cipherSeg.hex) {
            const cipherBuf = Buffer.from(cipherSeg.hex, 'hex');
            if (cipherBuf.length) {
                const markers = new Set([0x85, 0x86, 0x87, 0x90]);
                if (markers.has(cipherBuf[0])) {
                    const nestedResult = enhancedParseApdu(cipherBuf);
                    result.unifiedFormat.nestedApdu = nestedResult.unifiedFormat;
                }
            }
        }

        if (securityDataType === 2) {
            result.unifiedFormat.status = "失败";
        } else {
            result.unifiedFormat.status = "成功";
        }
    } catch (err) {
        result.unifiedFormat.error = `SECURITY-Response 解析失败: ${err.message}`;
    }
}

function parseSetResponse(apduBuffer, result) {
    let offset = 1; // 跳过 0x86
    result.unifiedFormat.type = "SET-Response";
    result.unifiedFormat.invokeId = apduBuffer[offset++] || 0;
    const responseType = apduBuffer[offset++] || 0; // 1: normal, 2: list

    if (responseType === 1) { // SetResponseNormal
        const oad = apduBuffer.slice(offset, offset + 4).toString('hex').toUpperCase(); offset += 4;
        result.unifiedFormat.oad = oad;
        result.unifiedFormat.objectInfo = getOADInfo(oad) || { desc: "未知对象" };
        const dar = apduBuffer[offset] !== undefined ? apduBuffer[offset] : 0xFF;
        result.unifiedFormat.status = (dar === 0x00) ? "成功" : "失败";
        result.unifiedFormat.error = (dar === 0x00) ? null : getDarDescription(dar);
    } else {
        result.unifiedFormat.error = `不支持的SET-Response类型: 0x${responseType.toString(16)}`;
    }
}

function parseActionResponse(apduBuffer, result) {
    let offset = 1; // 跳过 0x87
    result.unifiedFormat.type = "ACTION-Response";
    result.unifiedFormat.invokeId = apduBuffer[offset++] || 0;
    const responseType = apduBuffer[offset++] || 0; // 1: normal, 2: list

    if (responseType === 1) { // ActionResponseNormal
        // OMD（对象方法描述符），这里按 4 字节展示（与 OAD 等长，便于查看）
        const omd = apduBuffer.slice(offset, offset + 4).toString('hex').toUpperCase(); offset += 4;
        result.unifiedFormat.omd = omd;
        result.unifiedFormat.objectInfo = getOADInfo(omd) || { desc: "方法/动作响应" };

        // --- [新增] F3000500 (自动轮显) 的特殊处理 ---
        if (omd === 'F3000500') {
            // 这是一个自定义的SET-Response, 但设备使用ACTION-Response(0x87)返回
            // PIID(1) + OAD(4) + ResultList(1) + Result(2) + TimeTag(3)
            // 我们直接从 OMD 后面开始解析 payload
            const customPayload = apduBuffer.slice(offset);
            result.unifiedFormat.data = parseAutoDisplayResponse(customPayload);
            result.unifiedFormat.status = result.unifiedFormat.data.success ? "成功" : "失败";
            if (!result.unifiedFormat.data.success) {
                result.unifiedFormat.error = result.unifiedFormat.data.error;
            }
            return;
        }
        // --- 特殊处理结束 ---

        const dataResultChoice = apduBuffer[offset++] || 0; // 0: DAR, 1: data
        if (dataResultChoice === 0) {
            const dar = apduBuffer[offset] !== undefined ? apduBuffer[offset] : 0xFF;
            result.unifiedFormat.status = (dar === 0x00) ? "成功" : "失败";
            result.unifiedFormat.error = (dar === 0x00) ? null : getDarDescription(dar);
        } else {
            // 存在动作返回数据，复用通用解析
            const std = createStandardResult("动作结果", omd, apduBuffer.slice(offset));
            try {
                const { result: parsed } = enhancedParseData(apduBuffer.slice(offset), omd.slice(0, 4), omd.slice(4, 6));
                std.value = parsed.parsedValue;
                setSuccessResult(std, parsed, { generic: parsed });
            } catch (e) { setErrorResult(std, e.message); }
            result.unifiedFormat.status = "成功";
            result.unifiedFormat.data = std;
        }
    } else {
        result.unifiedFormat.error = `不支持的ACTION-Response类型: 0x${responseType.toString(16)}`;
    }
}

/**
 * [新增] 解析自动轮显设置响应 (OAD F3000500)
 * @param {Buffer} payload - APDU中OMD之后的数据部分
 * @returns {Object} - 标准解析结果对象
 */
function parseAutoDisplayResponse(payload) {
    const result = createStandardResult("自动轮显参数设置响应", 'F3000500', payload);
    try {
        // 根据用户提供的逐字节解析:
        // 字节 0: '14' (0x14) -> 结果数组长度, 但实际意为1个结果
        // 字节 1-2: '00 00' -> 结果码, 0为成功
        // 字节 3-5: '01 00 04' -> 时间标签(忽略)
        if (payload.length < 3) {
            throw new Error(`数据长度不足 (${payload.length}字节)，无法解析轮显响应`);
        }

        const resultCode = payload.readUInt16BE(1); // 读取字节1和2
        const success = (resultCode === 0x0000);

        const data = {
            description: "设置自动轮显参数的响应",
            success: success,
            resultCode: `0x${resultCode.toString(16).padStart(4, '0')}`,
            resultText: success ? "成功" : "失败",
            rawPayload: payload.toString('hex').toUpperCase()
        };

        result.value = success;
        setSuccessResult(result, data, {
            generic: {
                resultArrayLength: payload[0],
                resultCode: resultCode,
                timeTag: payload.length >= 6 ? payload.slice(3, 6).toString('hex') : null
            }
        });

    } catch (e) {
        setErrorResult(result, e.message);
    }
    return result;
}

function enhancedParseApdu(apduBuffer) {
    if (apduBuffer.length < 1) throw new Error("APDU长度不足");
    const apduType = apduBuffer[0];
    const result = { rawType: `0x${apduType.toString(16).toUpperCase()}`, unifiedFormat: { type: `未知APDU(0x${apduType.toString(16).toUpperCase()})` } };
    switch (apduType) {
        case 0x85: result.unifiedFormat.type = "GET-Response"; parseGetResponse(apduBuffer, result); break;
        case 0x82: result.unifiedFormat.type = "CONNECT-Response"; parseConnectResponse(apduBuffer, result); break;
        case 0x90: result.unifiedFormat.type = "SECURITY-Response"; parseSecurityResponse(apduBuffer, result); break;
        case 0x86: // SET-Response
            result.unifiedFormat.type = "SET-Response";
            parseSetResponse(apduBuffer, result);
            break;
        case 0x87: // ACTION-Response
            result.unifiedFormat.type = "ACTION-Response";
            parseActionResponse(apduBuffer, result);
            break;
        default:
            result.unifiedFormat.error = `不支持的APDU类型: 0x${apduType.toString(16).toUpperCase()}`;
            result.unifiedFormat.rawData = apduBuffer.toString('hex').toUpperCase();
    }
    return result;
}

/** ===================== 模式判定与主逻辑 ===================== */
function normalizePayloadToBuffer(payload) {
    if (Buffer.isBuffer(payload)) return payload;
    if (payload && typeof payload === 'object') {
        const hex = payload.hex || payload.raw;
        if (hex) {
            const sanitized = sanitizeHex(hex);
            if (!sanitized) throw new Error("hex/raw 字段为空，无法解码");
            return Buffer.from(sanitized, 'hex');
        }
    }
    if (typeof payload === 'string') {
        const sanitized = sanitizeHex(payload);
        if (!sanitized) throw new Error("字符串为空，无法解码");
        return Buffer.from(sanitized, 'hex');
    }
    throw new Error("输入格式不支持，无法解码");
}

function decideMode(msg) {
    const force = (msg.mode || msg.action || '').toString().toLowerCase();
    if (force === 'encode' || force === 'decode') return force;

    const p = msg.payload;
    if (Buffer.isBuffer(p)) return 'decode';

    if (typeof p === 'string') {
        const s = p.trim();
        if (looksLikeOADString(s)) return 'encode';
        if (isHexString(s) && looksLikeFrameHex(s)) return 'decode';
    }

    if (p && typeof p === 'object') {
        if (p.oad || looksLikeOADString(p?.oad)) return 'encode';
        if (p.hex || p.raw) {
            const h = sanitizeHex(p.hex || p.raw);
            if (looksLikeFrameHex(h)) return 'decode';
        }
    }
    try {
        const h = sanitizeHex(p);
        if (looksLikeFrameHex(h)) return 'decode';
    } catch (_) { }
    return 'encode';
}

// 处理消息
// let mode = 'unknown';
function batchMsg(_msg, mode) {
    // 在 try 外预声明，避免 catch 中未定义

    const _pdata = _msg.payload;
    const _tag = (_pdata && typeof _pdata === 'object') ? (_pdata.tag || '') : '';
    const effectiveMode = (mode === 'encode' || mode === 'decode') ? mode : decideMode(_msg);
    try {
        // mode = //decideMode(_msg);

        if (effectiveMode === 'encode') {
            // ---------- 编码（使用 Node-RED 698 编码器） ----------
            if (!_pdata) throw new Error("输入 (_msg.payload) 不能为空。");

            // 兼容字符串/对象两种输入
            let encInput;
            if (typeof _pdata === 'string') encInput = { oadHex: _pdata };
            else if (typeof _pdata === 'object') encInput = { ..._pdata };
            else throw new Error('不支持的输入类型用于编码');

            // 地址与控制字段映射
            if (_msg.com_exec_addr && !encInput.sa) encInput.sa = _msg.com_exec_addr;
            if (encInput.address && !encInput.sa) encInput.sa = encInput.address;
            if (encInput.clientAddress && !encInput.ca) { try { encInput.ca = parseInt(String(encInput.clientAddress), 16); } catch (_) {} }
            if (encInput.control && !encInput.ctrl) { try { encInput.ctrl = parseInt(String(encInput.control), 16); } catch (_) {} }
            if (encInput.preamble != null && encInput.prependFE == null) encInput.prependFE = !!encInput.preamble;
            // 兼容旧用法：oad 字符串 → oadHex
            if (typeof encInput.oad === 'string' && !encInput.oadHex) encInput.oadHex = encInput.oad;

            // 生成帧
            const hex = encode698(encInput);
            const finalFrame = Buffer.from(hex, 'hex');

            _msg.payload = hex.toUpperCase();
            _msg.frame_info = {
                length: finalFrame.length,
                description: `请求 ${encInput.oadHex || (encInput.oad ? ((encInput.oad.oi<<16 | encInput.oad.att<<8 | encInput.oad.index).toString(16).padStart(8,'0').toUpperCase()) : '')}`,
                params: encInput
            };
            _msg.meta = {
                mode: 'encode',
                address: encInput.sa,
                client: encInput.ca != null ? ('0x'+Number(encInput.ca).toString(16)) : undefined,
                oad: encInput.oadHex || undefined,
                tag: _tag,
                requestType: encInput.service || 'get',
                frameLen: finalFrame.length,
                time: new Date().toISOString()
            };
            _msg = Object.assign({}, _pdata, _msg);
            return _msg;

        } else {
            // ---------- 解码 ----------
            if (!_msg.payload) throw new Error("输入为空，无法解码。");

            const buffer = normalizePayloadToBuffer(_msg.payload);

            buffer = stripFE(buffer); // 去掉 0~4 个 FE

            const frameInfo = detectAndValidateFrame(buffer);
            if (!frameInfo) throw new Error(`帧格式无法识别或校验失败,payload: ${_msg.payload} ,输入 buffer: ${bufferSummary(buffer)}`);

            const apduBuffer = buffer.slice(frameInfo.apduStart, frameInfo.fcsStart);
            const result = enhancedParseApdu(apduBuffer);

            result.frameInfo = {
                address: frameInfo.address,
                serverAddress: frameInfo.serverAddress,
                clientAddress: frameInfo.clientAddress,
                saFlag: frameInfo.saFlag,
                declaredLength: frameInfo.declaredLength,
                lengthMatched: frameInfo.lengthMatched,
                totalLength: buffer.length,
                apduLength: apduBuffer.length
            };

            _msg.payload = result.unifiedFormat.data || result.unifiedFormat;
            _msg.decoding_details = result;
            _msg.meta = {
                mode: 'decode',
                address: frameInfo.address,
                apduType: result.unifiedFormat?.type,
                apduLen: apduBuffer.length,
                frameLen: buffer.length,
                time: new Date().toISOString()
            };

            return _msg;
        }

    } catch (err) {
        if (node && typeof node.error === 'function') node.error(`[DLT698-Codec] ${err.message}`, _msg);
        _msg.error = err.message;
        _msg._mode = mode;
        _msg.payload = null;
        return _msg;
    }
}

// 主执行逻辑
if (typeof msg !== 'undefined' && msg) {
    try {
        // let nMsg=Object.assign({},msg);
        let data = msg.payload
        let mode = msg.mode || 'unknown'
        if (Array.isArray(data)) {
            msg.payload = data.map((_msg) => {
                return batchMsg(_msg, mode);
            })
            return msg;
        } else {
            batchMsg(msg, mode);
            return msg;
        }

    } catch (error) {
        if (typeof node !== 'undefined' && node) {
            node.error(error);
            node.error("msg.payload 传入协议解析只支持String和Array", msg);
        }
    }
}



function bufferSummary(buf, maxFullSize = 1024) {
    if (!Buffer.isBuffer(buf)) {
        return String(buf);
    }

    const len = buf.length;

    // 如果超出安全阈值，只预览开头部分（防日志爆炸）
    if (len > maxFullSize) {
        const previewLen = 64; // 只看前 64 字节
        const hex = buf.subarray(0, previewLen).toString('hex');
        const spaced = hex.match(/.{1,2}/g)?.join(' ') || '';
        return `<Buffer length=${len} [${spaced} ...]> (truncated, full size > ${maxFullSize} bytes)`;
    }

    // 默认：完整输出整个 buffer 的 hex
    const hex = buf.toString('hex');
    const spaced = hex.match(/.{1,2}/g)?.join(' ') || '';
    return `<Buffer length=${len} [${spaced}]>`;
}

}

module.exports = { process698 };
const { CONFIG, getOADInfo } = require('./698/constants');
const { encode698 } = require('./698/encoder');
