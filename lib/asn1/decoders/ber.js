var inherits = require('inherits');

var asn1 = require('../../asn1');
var base = asn1.base;
var bignum = asn1.bignum;

// Import BER constants
var der = asn1.constants.der;

function BERDecoder(entity) {
  this.enc = 'ber';
  this.name = entity.name;
  this.entity = entity;

  // Construct base tree
  this.tree = new base.BERNode();
  this.tree._init(entity.body);
};
module.exports = BERDecoder;

BERDecoder.prototype.decode = function decode(data, options) {
  if (!(data instanceof base.DecoderBuffer))
    data = new base.DecoderBuffer(data, options);

  return this.tree._decode(data, options);
};
