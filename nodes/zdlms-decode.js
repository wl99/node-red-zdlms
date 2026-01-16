const { handleWithMode } = require('./common');

module.exports = function registerDecode(RED) {
  function ZdlmsDecodeNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    node.name = config.name;
    node.protocol = (config.protocol || 'auto').toString();

    node.on('input', (msg, send, done) => {
      node.status({ fill: 'blue', shape: 'ring', text: 'decoding...' });
      try {
        const out = handleWithMode(node, msg, 'decode');
        send(out);
        node.status({ fill: 'green', shape: 'dot', text: 'decoded' });
        done();
      } catch (err) {
        node.error(err, msg);
        node.status({ fill: 'red', shape: 'ring', text: 'decode failed' });
        done(err);
      }
    });
  }

  RED.nodes.registerType('zdlms-decode', ZdlmsDecodeNode);
};
