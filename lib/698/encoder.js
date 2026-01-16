// 698 编码模块：来源于原 698.js 中的 NR698_* 实现

function NR698_toHexU8(arr){ return Buffer.from(arr).toString('hex').toUpperCase(); }
function NR698_fromHex(str){ return Buffer.from(String(str||'').replace(/\s+/g,''), 'hex'); }
function NR698_u16le(x){ return [x & 0xFF, (x>>>8)&0xFF]; }
function NR698_pppfcs16(fcs, buf){
    for (let i=0;i<buf.length;i++){
        fcs ^= buf[i];
        for (let b=0;b<8;b++){
            if (fcs & 1) fcs = (fcs>>>1) ^ 0x8408; else fcs >>>= 1;
        }
    }
    return fcs>>>0;
}
function NR698_tryfcs16(buf){ let trial = NR698_pppfcs16(0xFFFF, buf); trial ^= 0xFFFF; return trial & 0xFFFF; }
const NR698_OAD_NO_SECURITY = new Set([ '40010200','40020200','40000200' ]);
const ESAMINFO_ALIAS = {
    key: 'ESAMINFO',
    oadHex: 'EE010200',
    oadList: ['40020200','F1000200','F1000300','F1000400','F1000500','F1000600','F1000700']
};
function NR698_parseOADHex(oadHex){
    const oh = (oadHex||'').toUpperCase();
    if (oh.length !== 8) throw new Error('oadHex must be 8 hex chars');
    return { oi: parseInt(oh.slice(0,4),16), att: parseInt(oh.slice(4,6),16), index: parseInt(oh.slice(6,8),16) };
}
function NR698_fromHexLoose(str){ if (!str) return Buffer.alloc(0); return Buffer.from(String(str).replace(/\s+/g,'').toUpperCase(), 'hex'); }
function NR698_buildDisplayStructDataHex(oadHex, u=0, stay=10){
    const o = NR698_parseOADHex(oadHex);
    const oiHi = (o.oi>>>8)&0xFF, oiLo=o.oi&0xFF;
    const uHex = (u & 0xFF).toString(16).padStart(2,'0');
    const stayHex = ((stay>>>8)&0xFF).toString(16).padStart(2,'0') + (stay&0xFF).toString(16).padStart(2,'0');
    return (
        '0203' + '5B00' + oiHi.toString(16).padStart(2,'0') + oiLo.toString(16).padStart(2,'0') +
        o.att.toString(16).padStart(2,'0') + o.index.toString(16).padStart(2,'0') + '11' + uHex + '12' + stayHex
    ).toUpperCase();
}
function NR698_pushBytes(dest, srcBuf){
    for (const b of srcBuf) dest.push(b & 0xFF);
}
function NR698_pushAxdrLengthAndHex(dest, hex){
    if (hex == null) return;
    const buf = NR698_fromHexLoose(hex);
    const len = buf.length;
    if (!Number.isFinite(len) || len < 0) throw new Error("长度编码失败");
    if (len < 0x80){
        dest.push(len);
    } else {
        const bytes = [];
        let value = len;
        while (value > 0){
            bytes.unshift(value & 0xFF);
            value >>= 8;
        }
        if (bytes.length > 4) throw new Error("长度超过编码范围");
        dest.push(0x80 | bytes.length);
        for (const b of bytes) dest.push(b);
    }
    NR698_pushBytes(dest, buf);
}
function NR698_u16beBytes(value, label='value'){
    const v = Number(value);
    if (!Number.isFinite(v) || v < 0 || v > 0xFFFF) throw new Error(`${label} must be 0~65535`);
    return [ (v >>> 8) & 0xFF, v & 0xFF ];
}
function NR698_u32beBytes(value, label='value'){
    const v = Number(value);
    if (!Number.isFinite(v) || v < 0 || v > 0xFFFFFFFF) throw new Error(`${label} must be 0~0xFFFFFFFF`);
    return [ (v >>> 24) & 0xFF, (v >>> 16) & 0xFF, (v >>> 8) & 0xFF, v & 0xFF ];
}
function NR698_pickFixedBytes(input, expectedLen, label, defaultHex=''){
    let val = input;
    if (val == null || val === '') val = defaultHex;
    if (val == null) throw new Error(`${label} is required`);
    if (typeof val === 'number') {
        if (expectedLen === 2) return NR698_u16beBytes(val, label);
        if (expectedLen === 4) return NR698_u32beBytes(val, label);
        val = val.toString(16).padStart(expectedLen * 2, '0');
    } else if (Array.isArray(val) || Buffer.isBuffer(val)) {
        const buf = Buffer.from(val);
        if (buf.length !== expectedLen) throw new Error(`${label} must be ${expectedLen} bytes`);
        return buf;
    }
    const buf = NR698_fromHexLoose(val);
    if (buf.length !== expectedLen) throw new Error(`${label} must be ${expectedLen} bytes`);
    return buf;
}
function NR698_appendLengthValueSegments(target, segments){
    for (const seg of segments){
        const hex = (seg && (seg.dataHex ?? seg.hex ?? seg.raw ?? seg)) || '';
        const buf = NR698_fromHexLoose(hex);
        if (buf.length > 255) throw new Error('Security segment length must be <=255 bytes');
        target.push(buf.length & 0xFF);
        NR698_pushBytes(target, buf);
    }
}
function NR698_buildConnectRequestApdu(p){
    const apdu=[];
    apdu.push(0x02); // CONNECT_REQUEST
    apdu.push((p.piid ?? 1) & 0xFF);

    const expectAppVer = NR698_pickFixedBytes(
        p.expectAppVersion ?? p.expectAppVersionHex,
        2,
        'expectAppVersion',
        '0016'
    );
    NR698_pushBytes(apdu, expectAppVer);

    const protocolBytes = NR698_pickFixedBytes(
        p.protocolBitmap ?? 'FFFFFFFFC0000000',
        8,
        'protocolBitmap'
    );
    NR698_pushBytes(apdu, protocolBytes);

    const functionBytes = NR698_pickFixedBytes(
        p.functionBitmap ?? 'FFFEC400000000000000000000000000',
        16,
        'functionBitmap'
    );
    NR698_pushBytes(apdu, functionBytes);

    NR698_pushBytes(apdu, NR698_u16beBytes(p.clientSendSize ?? 0x0200, 'clientSendSize'));
    NR698_pushBytes(apdu, NR698_u16beBytes(p.clientRecvSize ?? 0x0200, 'clientRecvSize'));

    apdu.push((p.clientRecvMaxWindow ?? 1) & 0xFF);
    NR698_pushBytes(apdu, NR698_u16beBytes(p.clientDealMaxApdu ?? 0x07D0, 'clientDealMaxApdu'));
    NR698_pushBytes(apdu, NR698_u32beBytes(p.expectConnectTimeout ?? 0x1C20, 'expectConnectTimeout'));

    const hasStructuredSecurity = Array.isArray(p.securitySegments) && p.securitySegments.length > 0;
    const hasObjectSecurity = p.securityPayload && typeof p.securityPayload === 'object' &&
        (p.securityPayload.cipherHex != null || p.securityPayload.signatureHex != null || p.securityPayload.extraHex != null);
    const hasRawSecurity = !!p.securityRawHex;
    let connectType = p.connectType;
    if (connectType == null) {
        connectType = (hasStructuredSecurity || hasObjectSecurity) ? 0x02 : 0x00;
    }
    apdu.push(connectType & 0xFF);

    if (hasStructuredSecurity) {
        NR698_appendLengthValueSegments(apdu, p.securitySegments);
    } else if (hasObjectSecurity) {
        const segs = [];
        if (p.securityPayload.cipherHex != null) segs.push(p.securityPayload.cipherHex);
        if (p.securityPayload.signatureHex != null) segs.push(p.securityPayload.signatureHex);
        if (p.securityPayload.extraHex != null) segs.push(p.securityPayload.extraHex);
        NR698_appendLengthValueSegments(apdu, segs);
    } else if (hasRawSecurity) {
        const raw = NR698_fromHexLoose(p.securityRawHex);
        NR698_pushBytes(apdu, raw);
    }

    return apdu;
}
function NR698_buildSecurityRequestApdu(p = {}){
    const apdu = [];
    apdu.push(0x10); // SECURITY_REQUEST
    const dataType = (p.securityDataType ?? p.securityType ?? 0) & 0xFF;
    apdu.push(dataType);
    if (p.securityDataUnitHex) {
        NR698_pushBytes(apdu, NR698_fromHexLoose(p.securityDataUnitHex));
    } else {
        const cipherHex = p.cipherHex ?? p.securityCipherHex ?? p.securityDataHex;
        if (cipherHex) {
            if (p.cipherEncoded) {
                NR698_pushBytes(apdu, NR698_fromHexLoose(cipherHex));
            } else {
                NR698_pushAxdrLengthAndHex(apdu, cipherHex);
            }
        } else if (dataType !== 0) {
            throw new Error("security request 缺少密文/数据字段");
        }
        if (p.cipherAppendHex) {
            NR698_pushAxdrLengthAndHex(apdu, p.cipherAppendHex);
        }
    }
    const verifyType = (p.securityVerifyType ?? p.verifyType ?? 0) & 0xFF;
    apdu.push(verifyType);
    if (p.securityVerifyUnitHex) {
        NR698_pushBytes(apdu, NR698_fromHexLoose(p.securityVerifyUnitHex));
    } else {
        const sidSegmentHex = p.sidSegmentHex ?? p.sidHex;
        if (sidSegmentHex != null) {
            NR698_pushBytes(apdu, NR698_fromHexLoose(sidSegmentHex));
        } else if (p.sidValueHex != null) {
            NR698_pushAxdrLengthAndHex(apdu, p.sidValueHex);
        }
        const sidAppendHex = p.sidAppendSegmentHex ?? p.sidAppendHex;
        if (sidAppendHex != null) {
            NR698_pushBytes(apdu, NR698_fromHexLoose(sidAppendHex));
        } else if (p.sidAppendValueHex != null) {
            NR698_pushAxdrLengthAndHex(apdu, p.sidAppendValueHex);
        }
        const macSegmentHex = p.macSegmentHex ?? p.macHex;
        if (macSegmentHex != null) {
            NR698_pushBytes(apdu, NR698_fromHexLoose(macSegmentHex));
        } else if (p.macValueHex != null) {
            NR698_pushAxdrLengthAndHex(apdu, p.macValueHex);
        }
    }
    return apdu;
}
function NR698_encOAD(oi, att, index){ return [ (oi>>>8)&0xFF, oi&0xFF, att&0xFF, index&0xFF ]; }
function NR698_normalizeOAD(entry){
    if (typeof entry === 'string'){
        return NR698_parseOADHex(entry);
    }
    if (entry && typeof entry === 'object'){
        if (typeof entry.oadHex === 'string'){
            return NR698_parseOADHex(entry.oadHex);
        }
        if (entry.oi != null){
            return {
                oi: entry.oi >>> 0,
                att: (entry.att != null ? entry.att : 0) & 0xFF,
                index: (entry.index != null ? entry.index : 0) & 0xFF
            };
        }
    }
    throw new Error('Invalid OAD entry');
}
function NR698_encRSD(rsd){ if (!rsd || rsd.choice==null) return []; const out=[]; out.push(rsd.choice & 0xFF); if (rsd.choice===9){ out.push((rsd.n||1)&0xFF); } else { throw new Error('RSD choice not implemented: '+rsd.choice); } return out; }
function NR698_encRCSD(rcsd){ if (!rcsd || !rcsd.csds || rcsd.csds.length===0){ return [0x00]; } const csds=rcsd.csds; const out=[]; out.push(csds.length&0xFF); for (const c of csds){ if (c.type==='oad'){ out.push(0x00); out.push(...NR698_encOAD(c.oi,c.att,c.index)); } else { throw new Error('RCSD CSD type not implemented: '+c.type); } } return out; }
function NR698_buildGetRequestApdu(p){
    const apdu=[];
    apdu.push(0x05);
    if (p.type==='normal'){
        apdu.push(0x01);
    }else if (p.type==='normal_list'){
        apdu.push(0x02);
    }else if (p.type==='record'){
        apdu.push(0x03);
    }else{
        throw new Error('Unsupported GET type: '+p.type);
    }
    apdu.push((p.piid ?? 1) & 0xFF);
    if (p.type==='normal'){
        if (!p.oad) throw new Error('OAD required');
        apdu.push(...NR698_encOAD(p.oad.oi,p.oad.att,p.oad.index));
    }else if (p.type==='normal_list'){
        if (!p.oadList || p.oadList.length===0) throw new Error('oadList required for normal_list');
        apdu.push(p.oadList.length & 0xFF);
        for (const entry of p.oadList){
            apdu.push(...NR698_encOAD(entry.oi, entry.att, entry.index));
        }
    }else if (p.type==='record'){
        if (!p.oad) throw new Error('OAD required');
        apdu.push(...NR698_encOAD(p.oad.oi,p.oad.att,p.oad.index));
        apdu.push(...NR698_encRSD(p.rsd));
        apdu.push(...NR698_encRCSD(p.rcsd));
    }
    apdu.push(0x00);
    return apdu;
}
function NR698_buildActionRequestApdu(p){ const apdu=[]; apdu.push(0x07); apdu.push(0x01); apdu.push((p.piid ?? 1)&0xFF); if (!p.oad) throw new Error('OAD required'); apdu.push(...NR698_encOAD(p.oad.oi,p.oad.att,p.oad.index)); const data = NR698_fromHexLoose(p.dataHex); for (const b of data) apdu.push(b); apdu.push(0x00); return apdu; }
function NR698_wrapSecurity(apdu, security, rnHex){ const out=[]; if (security==='none' || !security){ return apdu.slice(); } if (security==='plain' || security==='plain_rn'){ const len = apdu.length & 0xFF; out.push(0x10,0x00,len); out.push(...apdu); if (security==='plain_rn'){ let rn = NR698_fromHexLoose(rnHex); if (rn.length===0){ rn = NR698_fromHexLoose('01234567891234560123456789123456'); } if (rn.length<1 || rn.length>16) throw new Error('RN length must be 1..16 bytes'); out.push(0x01, rn.length & 0xFF); for (const b of rn) out.push(b); } return out; } throw new Error('Unsupported security: '+security); }
function NR698_buildFrame(params){
    const { saType=0, logicAddr=0, sa, ca=0x11, ctrl=0x43, prependFE=true, security='none', rn, service='get', type='normal', piid=0x01, oad, rsd, rcsd } = params;
    if (!sa || (sa.length%2)!==0) throw new Error('sa must be hex string');
    const saBufFwd = NR698_fromHex(sa);
    const saLen = saBufFwd.length; if (saLen<1 || saLen>16) throw new Error('sa length must be 1..16');
    const saFlag = ((saType&0x3)<<6) | ((logicAddr&0x3)<<4) | ((saLen-1)&0x0F);
    let apdu=[];
    const initialService = (params.service || service || 'get').toLowerCase();
    if (initialService==='get' && !params.action && params.oad && params.oad.oi===0xF300 && params.oad.att===0x05 && params.oad.index===0x00 && params._display_oad_hex){
        params.service='action'; const dataHex = NR698_buildDisplayStructDataHex(params._display_oad_hex, params.displayUnsigned||0, params.displayStay||10); params.dataHex=dataHex; if ((params.security==='plain_rn' || params.security==='auto' || params.security==null) && !params._userProvidedRnHex){ params.security = params.security || 'plain_rn'; params.rnHex = dataHex; }
    }
    const serviceResolved = (params.service || service || 'get').toLowerCase();
    const securityResolved = (params.security != null ? params.security : security);
    const rnResolved = (params.rnHex != null ? params.rnHex : rn);
    if (serviceResolved==='get') apdu = NR698_buildGetRequestApdu({type, piid, oad, oadList: params.oadList, rsd, rcsd});
    else if (serviceResolved==='action') apdu = NR698_buildActionRequestApdu({piid, oad, dataHex: params.dataHex});
    else if (serviceResolved==='connect') apdu = NR698_buildConnectRequestApdu({ ...params, piid });
    else if (serviceResolved==='security') apdu = NR698_buildSecurityRequestApdu(params);
    else throw new Error('Unsupported service: '+serviceResolved);
    apdu = NR698_wrapSecurity(apdu, securityResolved, rnResolved);
    const body=[]; body.push(0x00,0x00); body.push(ctrl & 0xFF); body.push(saFlag & 0xFF); for (const b of saBufFwd) body.push(b); body.push(ca & 0xFF); const hcsIndex = body.length; body.push(0x00,0x00); for (const b of apdu) body.push(b);
    const indexBeforeFCS = body.length; const lengthVal = (indexBeforeFCS + 2) & 0x3FFF; body[0]=lengthVal & 0xFF; body[1]=(lengthVal>>>8)&0xFF;
    const hcs = NR698_tryfcs16(Uint8Array.from(body.slice(0, hcsIndex))); const [hcsLo,hcsHi]=NR698_u16le(hcs); body[hcsIndex]=hcsLo; body[hcsIndex+1]=hcsHi;
    const fcs = NR698_tryfcs16(Uint8Array.from(body.slice(0, indexBeforeFCS))); const [fcsLo,fcsHi]=NR698_u16le(fcs); body.push(fcsLo,fcsHi,0x16);
    const frame=[]; if (prependFE){ frame.push(0xFE,0xFE,0xFE,0xFE); } frame.push(0x68); for (const b of body) frame.push(b);
    return NR698_toHexU8(frame);
}
function NR698_prepareParams(p){
    const params = p || {};
    let autoEsamList = false;
    if (typeof params.oadHex === 'string' && params.oadHex.toUpperCase() === ESAMINFO_ALIAS.key){
        params.oadHex = ESAMINFO_ALIAS.oadHex;
        autoEsamList = true;
    }
    if (typeof params.oadHex === 'string'){
        const hex = params.oadHex.toUpperCase().trim();
        const m = hex.match(/^([0-9A-F]{8})(?:-([0-9A-F]{8}))?(?:-([0-9]+))?$/);
        if (!m) throw new Error('oadHex must be 8 hex chars; optionally -<OAD> or -<RCSD_OAD>-<n>');
        const base = m[1]; const ext2 = m[2]; const ext3 = m[3];
        params.oad = NR698_parseOADHex(base); params.oadHex = base;
        if (ext2 != null){
            if (/^[0-9A-F]{8}$/.test(ext2)){
                if (base==='F3000500'){ params._display_oad_hex = ext2; }
                else { params._rcsd_oad_hex = ext2; if (ext3 != null) params._rsd_n = parseInt(ext3,10); }
            }
        }
    }
    if (typeof params.oadHexList === 'string'){
        const segments = params.oadHexList.split(/[,|\s]+/).map(seg => seg.trim()).filter(Boolean);
        if (segments.length){
            params.oadList = params.oadList || [];
            for (const seg of segments){
                params.oadList.push(NR698_parseOADHex(seg));
            }
        }
    }
    if (autoEsamList && (!params.oadList || params.oadList.length===0)){
        params.oadList = ESAMINFO_ALIAS.oadList.map(code => NR698_parseOADHex(code));
    }
    if (Array.isArray(params.oadList)){
        params.oadList = params.oadList.map(entry => NR698_normalizeOAD(entry));
    }
    const serviceLower = (params.service == null ? 'get' : String(params.service)).toLowerCase();
    params.service = serviceLower;
    if (serviceLower === 'get') {
        if (params.type==null) params.type = (params.rsd||params.rcsd) ? 'record' : 'normal';
        if (params.oadList && params.oadList.length){
            params.type = params.type === 'record' ? 'record' : 'normal_list';
        }
    }
    if (params.ca==null) params.ca = 0x11;
    if (params.prependFE==null) params.prependFE = true;
    if (serviceLower === 'get' && !params.oad && !(params.oadList && params.oadList.length)){ params.oad = { oi:0x4001, att:0x02, index:0x00 }; }
    if (params._rcsd_oad_hex && (!params.rcsd || !Array.isArray(params.rcsd.csds))){ const o = NR698_parseOADHex(params._rcsd_oad_hex); params.type='record'; params.rsd = params.rsd || { choice:9, n:(params._rsd_n>0?params._rsd_n:1) }; params.rcsd = { csds:[{ type:'oad', oi:o.oi, att:o.att, index:o.index }] }; }
    if (params.rcsd && Array.isArray(params.rcsd.csds)){ params.rcsd.csds = params.rcsd.csds.map(c=>{ if (typeof c==='string'){ const o=NR698_parseOADHex(c); return { type:'oad', oi:o.oi, att:o.att, index:o.index }; } else if (c && typeof c==='object'){ if (!c.type && c.oi!=null) return { type:'oad', oi:c.oi, att:c.att||0, index:c.index||0 }; return c; } throw new Error('Invalid RCSD CSD item'); }); }
    let primaryOad = params.oad;
    if (serviceLower !== 'connect' && (!primaryOad || primaryOad.oi == null) && params.oadList && params.oadList.length){
        primaryOad = params.oadList[0];
        params.oad = params.oad || primaryOad;
    }
    const oadKey = params.oadHex ? params.oadHex.toUpperCase() :
        (primaryOad ? (((primaryOad.oi<<16)|(primaryOad.att<<8)|primaryOad.index).toString(16).padStart(8,'0')) : null);
    if (params.security==null || params.security==='auto'){
        if (oadKey && NR698_OAD_NO_SECURITY.has(oadKey)) params.security='none';
        else if (serviceLower==='get') params.security='plain_rn';
        else params.security='none';
    }
    if (Object.prototype.hasOwnProperty.call(params,'rnHex')) params._userProvidedRnHex = true;
    if (params.security==='plain_rn' && !params.rn && !params.rnHex){ params.rnHex = '01234567891234560123456789123456'; }
    if (!params.sa){ if (NR698_OAD_NO_SECURITY.has(oadKey)){ params.saType = (params.saType==null)?1:params.saType; params.sa='AAAAAAAAAAAA'; } else { throw new Error('sa (server address) required'); } }
    return params;
}

function encode698(input){
    const p = (typeof input === 'string') ? { oadHex: input } : (input||{});
    const prepared = NR698_prepareParams({ ...p });
    return NR698_buildFrame(prepared);
}

module.exports = {
    encode698,
    NR698_prepareParams,
    NR698_buildFrame
};
