try {
  var asn1 = require('asn1.js');
} catch (e) {
  var asn1 = require('../..');
}

/**
 * RFC 5952 Cryptographic Message Syntax
 **/

var rfc5952 = exports;

// PKCS#7 content types OIDs
var contentTypeOIDs = {
  '1 2 840 113549 1 7 1': 'data',
  '1 2 840 113549 1 7 2': 'signedData',
  '1 2 840 113549 1 7 3': 'envelopedData',
  '1 2 840 113549 1 7 4': 'signedAndEnvelopedData',
  '1 2 840 113549 1 7 5': 'digestData',
  '1 2 840 113549 1 7 6': 'encryptedData'
};

var rfc2315 = require('../2315');
var rfc5280 = require('../5280');
var rfc3211 = require('../3211');

// DEFINITIONS IMPLICIT TAGS

// ContentInfo ::= SEQUENCE {
//   contentType ContentType,
//   content [0] EXPLICIT ANY DEFINED BY contentType }
rfc5952.ContentInfo = asn1.define('ContentInfo', function () {
  this.seq().obj(
    // TODO
    this.key('contentType').objid(contentTypeOIDs),
    this.key('content').explicit(0).use(function (obj) {
      // TODO
      return {
        // This is just an octstr but we don't have access to octstr() here
        data: rfc2315.Data,
        envelopedData: EnvelopedData,
        compressedData: CompressedData,
        signedData: SignedData,
        encryptedData: EncryptedData
      }[obj.contentType]
    })
  );
});

// This is taken from rfc3274 to avoid cicular dependency
// CompressedData ::= SEQUENCE {
//   version CMSVersion,
//   compressionAlgorithm CompressionAlgorithmIdentifier,
//   encapContentInfo EncapsulatedContentInfo
var CompressedData = asn1.define('CompressedData', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('compressionAlgorithm').use(rfc5280.AlgorithmIdentifier),
    this.key('encapContentInfo').use(EncapsulatedContentInfo)
  );
});
rfc5952.CompressedData = CompressedData;

// EnvelopedData ::= SEQUENCE {
//   version CMSVersion,
//   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//   recipientInfos RecipientInfos,
//   encryptedContentInfo EncryptedContentInfo,
//   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
//
// RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
// UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
var EnvelopedData = asn1.define('EnvelopedData', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('originatorInfo').implicit(0).optional().use(OriginatorInfo),
    this.key('recipientInfos').setof(RecipientInfo),
    this.key('encryptedContentInfo').use(EncryptedContentInfo),
    this.key('unprotectedAttrs').implicit(1).optional().seqof(rfc5280.AttributeTypeAndValue)
  );
});
rfc5952.EnvelopedData = EnvelopedData;

// EncryptedData ::= SEQUENCE {
//   version CMSVersion,
//   encryptedContentInfo EncryptedContentInfo,
//   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
var EncryptedData = asn1.define('EncryptedData', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('encryptedContentInfo').use(EncryptedContentInfo),
    this.key('unprotectedAttrs').implicit(1).optional().seqof(rfc5280.AttributeTypeAndValue)
  );
});
rfc5952.EncryptedData = EncryptedData;

// EncapsulatedContentInfo ::= SEQUENCE {
//   eContentType ContentType,
//   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
//
// ContentType ::= OBJECT IDENTIFIER
var EncapsulatedContentInfo = asn1.define('EncapsulatedContentInfo', function () {
  this.seq().obj(
    this.key('eContentType').objid(contentTypeOIDs),
    this.key('eContent').explicit(0).optional().octstr()
  );
});
rfc5952.EncapsulatedContentInfo = EncapsulatedContentInfo;

// SignedData ::= SEQUENCE {
//   version CMSVersion,
//   digestAlgorithms DigestAlgorithmIdentifiers,
//   encapContentInfo EncapsulatedContentInfo,
//   certificates [0] IMPLICIT CertificateSet OPTIONAL,
//   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//   signerInfos SignerInfos }
//
// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
// CertificateSet ::= SET OF CertificateChoices
// RevocationInfoChoices ::= SET OF RevocationInfoChoice
// SignerInfos ::= SET OF SignerInfo
var SignedData = asn1.define('SignedData', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('digestAlgorithms').setof(rfc5280.AlgorithmIdentifier),
    this.key('encapContentInfo').use(EncapsulatedContentInfo),
    this.key('certificates').implicit(0).optional().setof(CertificateChoices),
    this.key('crls').implicit(1).optional().setof(RevocationInfoChoice),
    this.key('signerInfos').setof(SignerInfo)
  );
});
rfc5952.SignedData = SignedData;

// SignerInfo ::= SEQUENCE {
//   version CMSVersion,
//   sid SignerIdentifier,
//   digestAlgorithm DigestAlgorithmIdentifier,
//   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//   signatureAlgorithm SignatureAlgorithmIdentifier,
//   signature SignatureValue,
//   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
//
// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
// SignatureValue ::= OCTET STRING
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
var SignerInfo = asn1.define('SignerInfo', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('sid').use(SignerIdentifier),
    this.key('digestAlgorithm').use(rfc5280.AlgorithmIdentifier),
    this.key('signedAttrs').implicit(0).optional().setof(rfc5280.Attribute),
    this.key('signatureAlgorithm').use(rfc5280.AlgorithmIdentifier),
    this.key('signature').octstr(),
    this.key('unsignedAttrs').implicit(1).optional().setof(rfc5280.Attribute)
  );
});
rfc5952.SignerInfo = SignerInfo;

// SignerIdentifier ::= CHOICE {
//   issuerAndSerialNumber IssuerAndSerialNumber,
//   subjectKeyIdentifier [0] SubjectKeyIdentifier }
var SignerIdentifier = asn1.define('SignerIdentifier', function () {
  this.choice({
    issuerAndSerialNumber: this.key('issuerAndSerialNumber').use(IssuerAndSerialNumber),
    subjectKeyIdentifier: this.key('subjectKeyIdentifier').implicit(0).octstr()
  });
});
rfc5952.SignerIdentifier = SignerIdentifier;

// CertificateChoices ::= CHOICE {
//   certificate Certificate,
//   extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
//   v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
//   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
//   other [3] IMPLICIT OtherCertificateFormat }
var CertificateChoices = asn1.define('CertificateChoices', function () {
  this.choice({
    certificate: this.key('certificate').use(rfc5280.Certificate),
    // TODO
    extendedCertificate: this.key('extendedCertificate').implicit(0).use(ExtendedCertificate),
    v1AttrCert: this.key('v1AttrCert').implicit(1).any(),
    v2AttrCert: this.key('v1AttrCert').implicit(2).any(),
    other: this.key('other').implicit(3).use(OtherCertificateFormat)
  });
});
rfc5952.CertificateChoices = CertificateChoices;

// OtherCertificateFormat ::= SEQUENCE {
//   otherCertFormat OBJECT IDENTIFIER,
//   otherCert ANY DEFINED BY otherCertFormat }
var OtherCertificateFormat = asn1.define('OtherCertificateFormat', function () {
  this.seq().obj(
    this.key('otherCertFormat').objid(),
    // TODO
    this.key('otherCert').any()
  );
});
rfc5952.OtherCertificateFormat = OtherCertificateFormat;

// RevocationInfoChoice ::= CHOICE {
//   crl CertificateList,
//   other [1] IMPLICIT OtherRevocationInfoFormat }
var RevocationInfoChoice = asn1.define('RevocationInfoChoice', function () {
  this.choice({
    crl: this.key('crl').use(rfc5280.CertificateList),
    other: this.key('other').implicit(1).use(OtherRevocationInfoFormat)
  });
});
rfc5952.RevocationInfoChoice = RevocationInfoChoice;

// OtherRevocationInfoFormat ::= SEQUENCE {
//   otherRevInfoFormat OBJECT IDENTIFIER,
//   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
var OtherRevocationInfoFormat = asn1.define('OtherRevocationFormat', function () {
  this.seq().obj(
    this.key('otherRevInfoFormat').objid(),
    // TODO
    this.key('otherRevInfo').any()
  );
});
rfc5952.OtherRevocationInfoFormat = OtherRevocationInfoFormat;

// OriginatorInfo ::= SEQUENCE {
//   certs [0] IMPLICIT CertificateSet OPTIONAL,
//   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
//
// CertificateSet ::= SET OF CertificateChoices
// RevocationInfoChoices ::= SET OF RevocationInfoChoice
var OriginatorInfo = asn1.define('OriginatorInfo', function () {
  this.seq().obj(
    this.key('certs').implicit(0).optional().setof(CertificateChoices),
    this.key('crls').implicit(1).optional().setof(RevocationInfoChoice)
  );
});
rfc5952.OriginatorInfo = OriginatorInfo;

// ExtendedCertificate ::= SEQUENCE {
//   extendedCertificateInfo ExtendedCertificateInfo,
//   signatureAlgorithm SignatureAlgorithmIdentifier,
//   signature Signature }
var ExtendedCertificate = asn1.define('ExtendedCertificate', function () {
  this.seq().obj(
    this.key('extendedCertificateInfo').use(ExtendedCertificateInfo),
    this.key('signatureAlgorithm').use(rfc5280.AlgorithmIdenfier),
    this.key('signature').bitstr()
  );
});
rfc5952.ExtendedCertificate = ExtendedCertificate;

// ExtendedCertificateInfo ::= SEQUENCE {
//   version CMSVersion,
//   certificate Certificate,
//   attributes UnauthAttributes }
var ExtendedCertificateInfo = asn1.define('ExtendedCertificateInfo', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('certificate').use(rfc5280.Certificate),
    this.key('attributes').setof(rfc5280.Attribute)
  );
});
rfc5952.ExtendedCertificateInfo ExtendedCertificateInfo;

// EncryptedContentInfo ::= SEQUENCE {
//   contentType ContentType,
//   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
//
// EncryptedContent ::= OCTET STRING
//
// ContentType ::= OBJECT IDENTIFIER
var EncryptedContentInfo = asn1.define('EncryptedContentInfo', function () {
  this.seq().obj(
    this.key('contentType').objid(contentTypeOIDs),
    this.key('contentEncryptionAlgorithm').use(rfc5280.AlgorithmIdentifier),
    this.key('encryptedContent').implicit(0).optional().octstr()
  );
});
rfc5952.EncryptedContentInfo = EncryptedContentInfo;

//  RecipientInfo ::= CHOICE {
//    ktri KeyTransRecipientInfo,
//    kari [1] KeyAgreeRecipientInfo,
//    kekri [2] KEKRecipientInfo,
//    pwri [3] PasswordRecipientinfo,
//    ori [4] OtherRecipientInfo }
var RecipientInfo = asn1.define('RecipientInfo', function () {
  this.choice({
    ktri: this.use(KeyTransRecipientInfo),
    // kari: this.implicit(1).use(KeyAgreeRecipientInfo),
    kekri: this.implicit(2).use(KEKRecipientInfo),
    pwri: this.implicit(3).use(rfc3211.PasswordRecipientInfo)
    // ori: this.implicit(4).use(OtherRecipientInfo)
  });
});
rfc5952.RecipientInfo = RecipientInfo;

// KeyTransRecipientInfo ::= SEQUENCE {
//   version CMSVersion,  -- always set to 0 or 2
//   rid RecipientIdentifier,
//   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//   encryptedKey EncryptedKey }
var KeyTransRecipientInfo = asn1.define('keyTransRecipientInfo', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('rid').use(RecipientIdentifier),
    this.key('keyEncryptionAlgorithm').use(rfc5280.AlgorithmIdentifier),
    this.key('encryptedKey').octstr()
  );
});
rfc5952.KeyTransRecipientInfo = KeyTransRecipientInfo;

// KEKRecipientInfo ::= SEQUENCE {
//   version CMSVersion,  -- always set to 4
//   kekid KEKIdentifier,
//   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//   encryptedKey EncryptedKey }
var KEKRecipientInfo = asn1.define('KEKRecipientInfo', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('kekid').use(KEKIdentifier),
    this.key('keyEncryptionAlgorithm').use(rfc5280.AlgorithmIdentifier),
    this.key('encryptedKey').octstr()
  );
});
rfc5952.KEKRecipientInfo = KEKRecipientInfo;

// KEKIdentifier ::= SEQUENCE {
//   keyIdentifier OCTET STRING,
//   date GeneralizedTime OPTIONAL,
//   other OtherKeyAttribute OPTIONAL }
var KEKIdentifier = asn1.define('KEKIdentifier', function () {
  this.seq().obj(
    this.key('keyIdentifier').octstr(),
    // TODO
    this.key('date').optional().any(),
    this.key('other').optional().any()
  );
});
rfc5952.KEKIdentifier = KEKIdentifier;

// RecipientIdentifier ::= CHOICE {
//   issuerAndSerialNumber IssuerAndSerialNumber,
//   subjectKeyIdentifier [0] SubjectKeyIdentifier }
var RecipientIdentifier = asn1.define('RecipientIdentifier', function () {
  this.choice({
    issuerAndSerialNumber: this.key('issuerAndSerialNumber').use(IssuerAndSerialNumber),
    subjectKeyIdentifier: this.key('subjectKeyIdentifier').implicit(0).octstr()
  });
});
rfc5952.RecipientIdentifier = RecipientIdentifier;

// IssuerAndSerialNumber ::= SEQUENCE {
//   issuer Name,
//   serialNumber CertificateSerialNumber }
var IssuerAndSerialNumber = asn1.define('IssuerAndSerialNumber', function () {
  this.seq().obj(
    this.key('issuer').use(rfc5280.Name),
    this.key('serialNumber').int()
  );
});
rfc5952.IssuerAndSerialNumber = IssuerAndSerialNumber;
