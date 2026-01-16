const { process645 } = require('../lib/645');
const { process698 } = require('../lib/698');

module.exports = function registerEncode(RED) {
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

  function ZdlmsEncodeNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    node.name = config.name;
    node.protocol = (config.protocol || 'auto').toString();

    node.on('input', (msg, send, done) => {
      try {
        const proto = resolveProtocol(node, msg);
        const workMsg = { ...msg, mode: 'encode', action: 'encode' };
        const out = proto.includes('698') ? process698(node, workMsg) : process645(node, workMsg);
        send(out);
        done();
      } catch (err) {
        node.error(err, msg);
        done(err);
      }
    });
  }

  RED.nodes.registerType('zdlms-encode', ZdlmsEncodeNode);
};
