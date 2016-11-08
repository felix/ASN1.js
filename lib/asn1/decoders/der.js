var inherits = require('inherits');

var asn1 = require('../../asn1');
var base = asn1.base;
var BERDecoder = require('./ber');
var DERNode = require('./ber');

function DERDecoder(entity) {
  this.enc = 'der';
  this.name = entity.name;
  this.entity = entity;

  // Construct base tree
  this.tree = new base.DERNode();
  this.tree._init(entity.body);
};
module.exports = DERDecoder;

inherits(DERDecoder, BERDecoder);
