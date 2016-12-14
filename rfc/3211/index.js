try {
  var asn1 = require('asn1.js');
} catch (e) {
  var asn1 = require('../..');
}

/**
 * RFC 3211 Password-based Encryption for CMS
 **/

var rfc3211 = exports;
var rfc5280 = require('../5280');

// DEFINITIONS IMPLICIT TAGS

// PasswordRecipientInfo ::= SEQUENCE {
//    version CMSVersion,   -- Always set to 0
//    keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier OPTIONAL,
//    keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//    encryptedKey EncryptedKey }
rfc3211.PasswordRecipientInfo = asn1.define('PasswordRecipientInfo', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('keyDerivationAlgorithm').implicit(0).optional().use(rfc5280.AlgorithmIdentifier),
    this.key('keyEncryptionAlgorithm').use(rfc5280.AlgorithmIdentifier),
    /*
    this.key('keyEncryptionAlgorithm').use(function (obj) {
      console.log('obj', obj)
      if (obj.algorithm === '1.2.840.113549.1.9.16.3.9') {
        return KeyEncryptionAlgorithmIdentifier
      } else {
        return rfc5280.AlgorithmIdentifier
      }
    }),
    */
    this.key('encryptedKey').octstr()
  );
});

// ??
var KeyEncryptionAlgorithmIdentifier = asn1.define('KeyEncryptionAlgorithmIdentifier', function () {
  this.seq().obj(
    this.key('id-alg-PWRI-KEK').objid(),
    this.key('kekEncryptionAlgo').use(rfc5280.AlgorithmIdentifier)
  )
})
rfc3211.KeyEncryptionAlgorithmIdentifier = KeyEncryptionAlgorithmIdentifier;
