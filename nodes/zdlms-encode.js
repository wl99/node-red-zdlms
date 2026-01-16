const { handleWithMode } = require('./common');

module.exports = function registerEncode(RED) {
  function ZdlmsEncodeNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    node.name = config.name;
    node.protocol = (config.protocol || 'auto').toString();

    node.on('input', (msg, send, done) => {
      node.status({ fill: 'blue', shape: 'ring', text: 'encoding...' });
      try {
        const out = handleWithMode(node, msg, 'encode');
        send(out);
        node.status({ fill: 'green', shape: 'dot', text: 'encoded' });
        done();
      } catch (err) {
        node.error(err, msg);
        node.status({ fill: 'red', shape: 'ring', text: 'encode failed' });
        done(err);
      }
    });
  }

  RED.nodes.registerType('zdlms-encode', ZdlmsEncodeNode);
};
