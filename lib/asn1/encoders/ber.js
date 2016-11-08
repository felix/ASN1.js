var inherits = require('inherits');
var asn1 = require('../../asn1');
var base = asn1.base;

function BEREncoder(entity) {
  this.enc = 'der';
  this.name = entity.name;
  this.entity = entity;

  // Construct base tree
  this.tree = new base.BERNode();
  this.tree._init(entity.body);
};
module.exports = BEREncoder;

BEREncoder.prototype.encode = function encode(data, reporter) {
  return this.tree._encode(data, reporter).join();
};
