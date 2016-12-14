var inherits = require('inherits');
var Reporter = require('../base/reporter').Reporter;
var BERNode = require('../base/ber')

function BEREncoder(entity) {
  this.enc = 'der';
  this.name = entity.name;
  this.entity = entity;

  // Construct base tree
  this.tree = new BERNode();
  this.tree._init(entity.body);
};
module.exports = BEREncoder;

BEREncoder.prototype.encode = function encode(data, stream, reporter) {
  reporter = reporter || new Reporter();
  reporter.stream = stream || new EncoderStream();
  return this.tree._encode(data, reporter).join();
};
