//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsECDHEKeyExchange.java
//

#include "AlertDescription.h"
#include "AsymmetricKeyParameter.h"
#include "Certificate.h"
#include "CertificateRequest.h"
#include "ClientCertificateType.h"
#include "Digest.h"
#include "DigestInputBuffer.h"
#include "DigitallySigned.h"
#include "ECDomainParameters.h"
#include "ECPrivateKeyParameters.h"
#include "ECPublicKeyParameters.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "SecurityParameters.h"
#include "SignatureAndHashAlgorithm.h"
#include "Signer.h"
#include "SignerInputBuffer.h"
#include "TeeInputStream.h"
#include "TlsContext.h"
#include "TlsCredentials.h"
#include "TlsECCUtils.h"
#include "TlsECDHEKeyExchange.h"
#include "TlsECDHKeyExchange.h"
#include "TlsFatalAlert.h"
#include "TlsSigner.h"
#include "TlsSignerCredentials.h"
#include "TlsUtils.h"
#include "java/io/InputStream.h"
#include "java/security/SecureRandom.h"
#include "java/util/Vector.h"

@implementation LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange

- (instancetype)initWithInt:(jint)keyExchange
         withJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms
               withIntArray:(IOSIntArray *)namedCurves
             withShortArray:(IOSShortArray *)clientECPointFormats
             withShortArray:(IOSShortArray *)serverECPointFormats {
  LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(self, keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats);
  return self;
}

- (void)processServerCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:(id<LibOrgBouncycastleCryptoTlsTlsCredentials>)serverCredentials {
  if (!([LibOrgBouncycastleCryptoTlsTlsSignerCredentials_class_() isInstance:serverCredentials])) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  [self processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:[((id<LibOrgBouncycastleCryptoTlsTlsCredentials>) nil_chk(serverCredentials)) getCertificate]];
  self->serverCredentials_ = (id<LibOrgBouncycastleCryptoTlsTlsSignerCredentials>) cast_check(serverCredentials, LibOrgBouncycastleCryptoTlsTlsSignerCredentials_class_());
}

- (IOSByteArray *)generateServerKeyExchange {
  LibOrgBouncycastleCryptoTlsDigestInputBuffer *buf = new_LibOrgBouncycastleCryptoTlsDigestInputBuffer_init();
  self->ecAgreePrivateKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_generateEphemeralServerKeyExchangeWithJavaSecuritySecureRandom_withIntArray_withShortArray_withJavaIoOutputStream_([((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecureRandom], namedCurves_, clientECPointFormats_, buf);
  LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *signatureAndHashAlgorithm = LibOrgBouncycastleCryptoTlsTlsUtils_getSignatureAndHashAlgorithmWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsTlsSignerCredentials_(context_, serverCredentials_);
  id<LibOrgBouncycastleCryptoDigest> d = LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_(signatureAndHashAlgorithm);
  LibOrgBouncycastleCryptoTlsSecurityParameters *securityParameters = [((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecurityParameters];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(d)) updateWithByteArray:((LibOrgBouncycastleCryptoTlsSecurityParameters *) nil_chk(securityParameters))->clientRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->clientRandom_))->size_];
  [d updateWithByteArray:securityParameters->serverRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->serverRandom_))->size_];
  [buf updateDigestWithLibOrgBouncycastleCryptoDigest:d];
  IOSByteArray *hash_ = [IOSByteArray newArrayWithLength:[d getDigestSize]];
  [d doFinalWithByteArray:hash_ withInt:0];
  IOSByteArray *signature = [((id<LibOrgBouncycastleCryptoTlsTlsSignerCredentials>) nil_chk(serverCredentials_)) generateCertificateSignatureWithByteArray:hash_];
  LibOrgBouncycastleCryptoTlsDigitallySigned *signed_params = new_LibOrgBouncycastleCryptoTlsDigitallySigned_initWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(signatureAndHashAlgorithm, signature);
  [signed_params encodeWithJavaIoOutputStream:buf];
  return [buf toByteArray];
}

- (void)processServerKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input {
  LibOrgBouncycastleCryptoTlsSecurityParameters *securityParameters = [((id<LibOrgBouncycastleCryptoTlsTlsContext>) nil_chk(context_)) getSecurityParameters];
  LibOrgBouncycastleCryptoTlsSignerInputBuffer *buf = new_LibOrgBouncycastleCryptoTlsSignerInputBuffer_init();
  JavaIoInputStream *teeIn = new_LibOrgBouncycastleUtilIoTeeInputStream_initWithJavaIoInputStream_withJavaIoOutputStream_(input, buf);
  LibOrgBouncycastleCryptoParamsECDomainParameters *curve_params = LibOrgBouncycastleCryptoTlsTlsECCUtils_readECParametersWithIntArray_withShortArray_withJavaIoInputStream_(namedCurves_, clientECPointFormats_, teeIn);
  IOSByteArray *point = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque8WithJavaIoInputStream_(teeIn);
  LibOrgBouncycastleCryptoTlsDigitallySigned *signed_params = [self parseSignatureWithJavaIoInputStream:input];
  id<LibOrgBouncycastleCryptoSigner> signer = [self initVerifyerWithLibOrgBouncycastleCryptoTlsTlsSigner:tlsSigner_ withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:[((LibOrgBouncycastleCryptoTlsDigitallySigned *) nil_chk(signed_params)) getAlgorithm] withLibOrgBouncycastleCryptoTlsSecurityParameters:securityParameters];
  [buf updateSignerWithLibOrgBouncycastleCryptoSigner:signer];
  if (![((id<LibOrgBouncycastleCryptoSigner>) nil_chk(signer)) verifySignatureWithByteArray:[signed_params getSignature]]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_decrypt_error);
  }
  self->ecAgreePublicKey_ = LibOrgBouncycastleCryptoTlsTlsECCUtils_validateECPublicKeyWithLibOrgBouncycastleCryptoParamsECPublicKeyParameters_(LibOrgBouncycastleCryptoTlsTlsECCUtils_deserializeECPublicKeyWithShortArray_withLibOrgBouncycastleCryptoParamsECDomainParameters_withByteArray_(clientECPointFormats_, curve_params, point));
}

- (void)validateCertificateRequestWithLibOrgBouncycastleCryptoTlsCertificateRequest:(LibOrgBouncycastleCryptoTlsCertificateRequest *)certificateRequest {
  IOSShortArray *types = [((LibOrgBouncycastleCryptoTlsCertificateRequest *) nil_chk(certificateRequest)) getCertificateTypes];
  for (jint i = 0; i < ((IOSShortArray *) nil_chk(types))->size_; ++i) {
    switch (IOSShortArray_Get(types, i)) {
      case LibOrgBouncycastleCryptoTlsClientCertificateType_rsa_sign:
      case LibOrgBouncycastleCryptoTlsClientCertificateType_dss_sign:
      case LibOrgBouncycastleCryptoTlsClientCertificateType_ecdsa_sign:
      break;
      default:
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_illegal_parameter);
    }
  }
}

- (void)processClientCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:(id<LibOrgBouncycastleCryptoTlsTlsCredentials>)clientCredentials {
  if ([LibOrgBouncycastleCryptoTlsTlsSignerCredentials_class_() isInstance:clientCredentials]) {
  }
  else {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
}

- (id<LibOrgBouncycastleCryptoSigner>)initVerifyerWithLibOrgBouncycastleCryptoTlsTlsSigner:(id<LibOrgBouncycastleCryptoTlsTlsSigner>)tlsSigner
                                  withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:(LibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                         withLibOrgBouncycastleCryptoTlsSecurityParameters:(LibOrgBouncycastleCryptoTlsSecurityParameters *)securityParameters {
  id<LibOrgBouncycastleCryptoSigner> signer = [((id<LibOrgBouncycastleCryptoTlsTlsSigner>) nil_chk(tlsSigner)) createVerifyerWithLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:algorithm withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:self->serverPublicKey_];
  [((id<LibOrgBouncycastleCryptoSigner>) nil_chk(signer)) updateWithByteArray:((LibOrgBouncycastleCryptoTlsSecurityParameters *) nil_chk(securityParameters))->clientRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->clientRandom_))->size_];
  [signer updateWithByteArray:securityParameters->serverRandom_ withInt:0 withInt:((IOSByteArray *) nil_chk(securityParameters->serverRandom_))->size_];
  return signer;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 7, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 2, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoSigner;", 0x4, 9, 10, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withJavaUtilVector:withIntArray:withShortArray:withShortArray:);
  methods[1].selector = @selector(processServerCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:);
  methods[2].selector = @selector(generateServerKeyExchange);
  methods[3].selector = @selector(processServerKeyExchangeWithJavaIoInputStream:);
  methods[4].selector = @selector(validateCertificateRequestWithLibOrgBouncycastleCryptoTlsCertificateRequest:);
  methods[5].selector = @selector(processClientCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:);
  methods[6].selector = @selector(initVerifyerWithLibOrgBouncycastleCryptoTlsTlsSigner:withLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm:withLibOrgBouncycastleCryptoTlsSecurityParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serverCredentials_", "LLibOrgBouncycastleCryptoTlsTlsSignerCredentials;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ILJavaUtilVector;[I[S[S", "processServerCredentials", "LLibOrgBouncycastleCryptoTlsTlsCredentials;", "LJavaIoIOException;", "processServerKeyExchange", "LJavaIoInputStream;", "validateCertificateRequest", "LLibOrgBouncycastleCryptoTlsCertificateRequest;", "processClientCredentials", "initVerifyer", "LLibOrgBouncycastleCryptoTlsTlsSigner;LLibOrgBouncycastleCryptoTlsSignatureAndHashAlgorithm;LLibOrgBouncycastleCryptoTlsSecurityParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange = { "TlsECDHEKeyExchange", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 7, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange;
}

@end

void LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange *self, jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  LibOrgBouncycastleCryptoTlsTlsECDHKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(self, keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats);
  self->serverCredentials_ = nil;
}

LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange, initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_, keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats)
}

LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange_initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_(jint keyExchange, JavaUtilVector *supportedSignatureAlgorithms, IOSIntArray *namedCurves, IOSShortArray *clientECPointFormats, IOSShortArray *serverECPointFormats) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange, initWithInt_withJavaUtilVector_withIntArray_withShortArray_withShortArray_, keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats, serverECPointFormats)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsTlsECDHEKeyExchange)