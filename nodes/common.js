const { process645 } = require('../lib/645');
const { process698 } = require('../lib/698');

function resolveProtocol(node, msg) {
  const cfg = (node.protocol || 'auto').toLowerCase();
  const msgProto =
    (msg.protocol || (msg.payload && msg.payload.protocol) || '')
      .toString()
      .toLowerCase();
  if (msgProto) return msgProto;
  if (cfg !== 'auto') return cfg;

  const p = msg.payload;
  if (p && typeof p === 'object') {
    if (p.service || p.oadHex || p.ca != null || p.sa != null || p.ctrl != null) {
      return '698';
    }
  }
  return '645';
}

function handleWithMode(node, msg, fixedMode) {
  const proto = resolveProtocol(node, msg);
  const workMsg = { ...msg, mode: fixedMode, action: fixedMode };
  return proto.includes('698') ? process698(node, workMsg) : process645(node, workMsg);
}

module.exports = {
  resolveProtocol,
  handleWithMode
};
