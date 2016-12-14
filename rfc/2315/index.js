try {
  var asn1 = require('asn1.js');
} catch (e) {
  var asn1 = require('../..');
}

/**
 * RFC2315 PKCS #7: Cryptographic Message Syntax Version 1.5
 **/

var rfc2315 = exports;
var rfc5280 = require('../5280');

// Data ::= OCTET STRING
rfc2315.Data = asn1.define('Data', function () {
  this.octstr();
});

// DigestInfo ::= SEQUENCE {
//   digestAlgorithm DigestAlgorithmIdentifier,
//   digest Digest }
//
// Digest ::= OCTET STRING
rfc2315.DigestInfo = asn1.define('DigestInfo', function () {
  this.seq().obj(
    this.key('digestAlgorithm').use(rfc5280.AlgorithmIdentifier),
    this.key('digest').octstr()
  );
});
