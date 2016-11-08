var inherits = require('inherits');

var asn1 = require('../../asn1');
var base = asn1.base;
var bignum = asn1.bignum;
var Node = require('./node');
var BERNode = require('./ber');

function DERNode(parent) {
  Node.call(this, 'der', parent);
}
module.exports = DERNode;

inherits(DERNode, BERNode);

DERNode.prototype.decodeLen = function (buf, primitive, fail) {
  var len = buf.readUInt8(fail);
  if (buf.isError(len))
    return len;

  // Indefinite form
  if (!primitive && len === 0x80) {
    if (buf._reporterState.options.strict)
      return buf.error('Strict DER does not allow indefinite length');
    else
      return null;
  }

  // Definite form
  if ((len & 0x80) === 0) {
    // Short form
    return len;
  }

  // Long form
  var num = len & 0x7f;

  len = 0;
  for (var i = 0; i < num; i++) {
    len <<= 8;
    var j = buf.readUInt8(fail);
    if (buf.isError(j))
      return j;
    len |= j;
  }

  return len;
}
