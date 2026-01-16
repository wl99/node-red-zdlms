const { process645 } = require('../lib/645');
const { process698 } = require('../lib/698');

module.exports = function register(RED) {
  function ZdlmsNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    node.name = config.name;
    node.protocol = (config.protocol || 'auto').toString();

    function resolveProtocol(msg) {
      const cfg = (node.protocol || 'auto').toLowerCase();
      const msgProto =
        (msg.protocol ||
          (msg.payload && msg.payload.protocol) ||
          '').toString().toLowerCase();
      if (msgProto) return msgProto;
      if (cfg !== 'auto') return cfg;

      // Heuristic: if payload carries 698-style fields, prefer 698
      const p = msg.payload;
      if (p && typeof p === 'object') {
        if (p.service || p.oadHex || p.ca != null || p.sa != null || p.ctrl != null) {
          return '698';
        }
      }
      return '645';
    }

    node.on('input', (msg, send, done) => {
      try {
        const proto = resolveProtocol(msg);
        let out;
        if (proto.includes('698')) {
          out = process698(node, msg);
        } else {
          out = process645(node, msg);
        }
        send(out);
        done();
      } catch (err) {
        node.error(err, msg);
        done(err);
      }
    });
  }

  RED.nodes.registerType('zdlms', ZdlmsNode);
};
