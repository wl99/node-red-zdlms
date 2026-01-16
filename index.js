/**
 * Entry point for consumers outside Node-RED.
 * Exposes library helpers while Node-RED loads nodes via package.json "node-red".
 */
const { process645 } = require('./lib/645');
const { process698 } = require('./lib/698');

module.exports = {
  process645,
  process698
};
