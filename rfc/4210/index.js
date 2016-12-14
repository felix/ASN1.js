'use strict'

/**
 * RFC 4210 schema
 *
 * Internet X.509 Public Key Infrastructure
 * Certificate Management Protocol (CMP)
 *
 * @see {@link https://tools.ietf.org/html/rfc4210}
 *
 * @module schemas/rfc4210
 **/

var asn = require('asn1.js')
var oids = require('./oids')
var rfc5280 = require('./rfc5280')
var rfc4211 = require('./rfc4211')

// PKIMessage ::= SEQUENCE {
//     header           PKIHeader,
//     body             PKIBody,
//     protection   [0] PKIProtection OPTIONAL,
//     extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL
// }
var PKIMessage = asn.define('PKIMessage', function () {
  this.seq().obj(
    this.key('header').use(PKIHeader),
    this.key('body').use(PKIBody),
    this.key('protection').optional().explicit(0).bitstr(),
    this.key('extraCerts').optional().explicit(1).seqof(rfc5280.Certificate)
  )
})
exports.PKIMessage = PKIMessage

// PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
exports.PKIMessages = asn.define('PKIMessages', function () {
  this.seqof(PKIMessage)
})

// PKIHeader ::= SEQUENCE {
//     pvno                INTEGER     { cmp1999(1), cmp2000(2) },
//     sender              GeneralName,
//     recipient           GeneralName,
//     messageTime     [0] GeneralizedTime         OPTIONAL,
//     protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
//     senderKID       [2] KeyIdentifier           OPTIONAL,
//     recipKID        [3] KeyIdentifier           OPTIONAL,
//     transactionID   [4] OCTET STRING            OPTIONAL,
//     senderNonce     [5] OCTET STRING            OPTIONAL,
//     recipNonce      [6] OCTET STRING            OPTIONAL,
//     freeText        [7] PKIFreeText             OPTIONAL,
//     generalInfo     [8] SEQUENCE SIZE (1..MAX) OF InfoTypeAndValue     OPTIONAL
// }
var PKIHeader = asn.define('PKIHeader', function () {
  this.key('header').seq().obj(
    this.key('pvno').int(),
    this.key('sender').use(rfc5280.GeneralName),
    this.key('recipient').use(rfc5280.GeneralName),
    this.explicit(1).key('protectionAlg').optional().use(rfc5280.AlgorithmIdentifier),
    // TODO
    this.explicit(4).key('transactionID').optional().octstr(),
    this.explicit(5).key('senderNonce').optional().octstr(),
    this.explicit(6).key('recipNonce').optional().octstr(),
    this.explicit(7).key('freeText').optional().use(PKIFreeText),
    this.explicit(8).key('generalInfo').optional().seqof(InfoTypeAndValue)
  )
})
exports.PKIHeader = PKIHeader

// PKIBody ::= CHOICE {
//     ir       [0]  CertReqMessages,       --Initialization Req
//     ip       [1]  CertRepMessage,        --Initialization Resp
//     cr       [2]  CertReqMessages,       --Certification Req
//     cp       [3]  CertRepMessage,        --Certification Resp
//     p10cr    [4]  CertificationRequest,  --PKCS #10 Cert.  Req.
//     popdecc  [5]  POPODecKeyChallContent --pop Challenge
//     popdecr  [6]  POPODecKeyRespContent, --pop Response
//     kur      [7]  CertReqMessages,       --Key Update Request
//     kup      [8]  CertRepMessage,        --Key Update Response
//     krr      [9]  CertReqMessages,       --Key Recovery Req
//     krp      [10] KeyRecRepContent,      --Key Recovery Resp
//     rr       [11] RevReqContent,         --Revocation Request
//     rp       [12] RevRepContent,         --Revocation Response
//     ccr      [13] CertReqMessages,       --Cross-Cert.  Request
//     ccp      [14] CertRepMessage,        --Cross-Cert.  Resp
//     ckuann   [15] CAKeyUpdAnnContent,    --CA Key Update Ann.
//     cann     [16] CertAnnContent,        --Certificate Ann.
//     rann     [17] RevAnnContent,         --Revocation Ann.
//     crlann   [18] CRLAnnContent,         --CRL Announcement
//     pkiconf  [19] PKIConfirmContent,     --Confirmation
//     nested   [20] NestedMessageContent,  --Nested Message
//     genm     [21] GenMsgContent,         --General Message
//     genp     [22] GenRepContent,         --General Response
//     error    [23] ErrorMsgContent,       --Error Message
//     certConf [24] CertConfirmContent,    --Certificate confirm
//     pollReq  [25] PollReqContent,        --Polling request
//     pollRep  [26] PollRepContent         --Polling response
// }
var PKIBody = asn.define('PKIBody', function () {
  this.choice({
    // TODO
    ir: this.key('ir').explicit(0).seqof(rfc4211.CertReqMsg),
    ip: this.key('ip').explicit(1).use(CertRepMessage),
    // TODO
    pkiconf: this.key('pkiconf').explicit(19).any(),
    // TODO
    genm: this.key('genm').explicit(21).seqof(InfoTypeAndValue),
    genp: this.key('genp').explicit(22).seqof(InfoTypeAndValue),
    error: this.key('error').explicit(23).use(ErrorMsgContent),
    // TODO
    certConf: this.key('certConf').explicit(24).seqof(CertStatus)
  // TODO
  })
})
exports.PKIBody = PKIBody

/**
// CertConfirmContent ::= SEQUENCE OF CertStatus
var CertConfirmContent = asn.define('CertConfirmContent', function() {
    this.seqof(CertStatus)
})
**/

// CertStatus ::= SEQUENCE {
//    certHash    OCTET STRING,
//    certReqId   INTEGER,
//    statusInfo  PKIStatusInfo OPTIONAL
// }
var CertStatus = asn.define('CertStatus', function () {
  this.seq().obj(
    this.key('certHash').octstr(),
    this.key('certReqId').int(),
    this.key('statusInfo').optional().use(PKIStatusInfo)
  )
})

// PKIStatusInfo ::= SEQUENCE {
//     status        PKIStatus,
//     statusString  PKIFreeText     OPTIONAL,
//     failInfo      PKIFailureInfo  OPTIONAL
// }
var PKIStatusInfo = asn.define('PKIStatusInfo', function () {
  this.seq().obj(
    this.key('status').int(),
    this.key('statusString').optional().use(PKIFreeText),
    this.key('failInfo').optional().bitstr()
  )
})

// PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
var PKIFreeText = asn.define('PKIFreeText', function () {
  this.seq().obj(
    this.utf8str()
  )
})

// CertRepMessage ::= SEQUENCE {
//     caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
//     response         SEQUENCE OF CertResponse
// }
var CertRepMessage = asn.define('CertRepMessage', function () {
  this.seq().obj(
    this.key('caPubs').explicit(1).optional().seqof(rfc5280.Certificate),
    this.key('response').seqof(CertResponse)
  )
})

// CertifiedKeyPair ::= SEQUENCE {
//    certOrEncCert       CertOrEncCert,
//    privateKey      [0] EncryptedValue      OPTIONAL,
//    publicationInfo [1] PKIPublicationInfo  OPTIONAL
// }
var CertifiedKeyPair = asn.define('CertifiedKeyPair', function () {
  this.seq().obj(
    this.key('certOrEncCert').use(CertOrEncCert),
    this.key('privateKey').optional().explicit(0).use(rfc4211.EncryptedValue),
    this.key('publicationInfo').optional().explicit(1).use(PKIPublicationInfo)
  )
})

// ErrorMsgContent ::= SEQUENCE {
//     pKIStatusInfo          PKIStatusInfo,
//     errorCode              INTEGER           OPTIONAL,
//     errorDetails           PKIFreeText       OPTIONAL
// }
var ErrorMsgContent = asn.define('ErrorMsgContent', function () {
  this.seq().obj(
    this.key('pKIStatusInfo').use(PKIStatusInfo),
    this.key('errorCode').optional().int(),
    this.key('errorDetails').optional().use(PKIFreeText)
  )
})

// CertResponse ::= SEQUENCE {
//     certReqId           INTEGER,
//     status              PKIStatusInfo,
//     certifiedKeyPair    CertifiedKeyPair    OPTIONAL,
//     rspInfo             OCTET STRING        OPTIONAL
var CertResponse = asn.define('CertResponse', function () {
  this.seq().obj(
    this.key('certReqId').int(),
    this.key('status').use(PKIStatusInfo),
    this.key('certifiedKeyPair').optional().use(CertifiedKeyPair),
    this.key('repInfo').optional().octstr()
  )
})

/**
// GenRepContent ::= SEQUENCE OF InfoTypeAndValue
var GenRepContent = asn.define('GenRepContent', function() {
    this.seqof(InfoTypeAndValue)
})
**/

// InfoTypeAndValue ::= SEQUENCE {
//     infoType               OBJECT IDENTIFIER,
//     infoValue              ANY DEFINED BY infoType  OPTIONAL
// }
var InfoTypeAndValue = asn.define('InfoTypeAndValue', function () {
  this.seq().obj(
    this.key('infoType').objid(oids.byOID),
    this.key('infoValue').optional().any()
  )
})

// CertOrEncCert ::= CHOICE {
//     certificate     [0] Certificate,
//     encryptedCert   [1] EncryptedValue
// }
var CertOrEncCert = asn.define('CertOrEncCert', function () {
  this.choice({
    certificate: this.key('certificate').explicit(0).use(rfc5280.Certificate),
    encryptedCert: this.key('encryptedCert').explicit(1).use(rfc4211.EncryptedValue)
  })
})

// PKIPublicationInfo ::= SEQUENCE {
//     action     INTEGER {
//                     dontPublish (0),
//                     pleasePublish (1) },
//     pubInfos  SEQUENCE SIZE (1..MAX) OF SinglePubInfo OPTIONAL }
var PKIPublicationInfo = asn.define('PKIPublicationInfo', function () {
  this.seq().obj(
    this.key('action').int(),
    this.key('pubInfos').optional().seqof(SinglePubInfo)
  )
})

// SinglePubInfo ::= SEQUENCE {
//         pubMethod    INTEGER {
//             dontCare    (0),
//             x500        (1),
//             web         (2),
//             ldap        (3) },
//         pubLocation  GeneralName OPTIONAL }
var SinglePubInfo = asn.define('SinglePubInfo', function () {
  this.seq().obj(
    this.key('pubMethod').int(),
    this.key('pubLocation').optional().use(rfc5280.GeneralName)
  )
})
