//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsRSAKeyExchange.java
//

#include "AbstractTlsKeyExchange.h"
#include "AlertDescription.h"
#include "AsymmetricKeyParameter.h"
#include "Certificate.h"
#include "CertificateRequest.h"
#include "ClientCertificateType.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyExchangeAlgorithm.h"
#include "KeyUsage.h"
#include "PublicKeyFactory.h"
#include "RSAKeyParameters.h"
#include "Streams.h"
#include "SubjectPublicKeyInfo.h"
#include "TlsContext.h"
#include "TlsCredentials.h"
#include "TlsEncryptionCredentials.h"
#include "TlsFatalAlert.h"
#include "TlsRSAKeyExchange.h"
#include "TlsRSAUtils.h"
#include "TlsSignerCredentials.h"
#include "TlsUtils.h"
#include "X509Certificate.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/RuntimeException.h"
#include "java/math/BigInteger.h"
#include "java/util/Vector.h"

@implementation LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)supportedSignatureAlgorithms {
  LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange_initWithJavaUtilVector_(self, supportedSignatureAlgorithms);
  return self;
}

- (void)skipServerCredentials {
  @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unexpected_message);
}

- (void)processServerCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:(id<LibOrgBouncycastleCryptoTlsTlsCredentials>)serverCredentials {
  if (!([LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials_class_() isInstance:serverCredentials])) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  [self processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:[((id<LibOrgBouncycastleCryptoTlsTlsCredentials>) nil_chk(serverCredentials)) getCertificate]];
  self->serverCredentials_ = (id<LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials>) cast_check(serverCredentials, LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials_class_());
}

- (void)processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:(LibOrgBouncycastleCryptoTlsCertificate *)serverCertificate {
  if ([((LibOrgBouncycastleCryptoTlsCertificate *) nil_chk(serverCertificate)) isEmpty]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_bad_certificate);
  }
  LibOrgBouncycastleAsn1X509X509Certificate *x509Cert = [serverCertificate getCertificateAtWithInt:0];
  LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *keyInfo = [((LibOrgBouncycastleAsn1X509X509Certificate *) nil_chk(x509Cert)) getSubjectPublicKeyInfo];
  @try {
    self->serverPublicKey_ = LibOrgBouncycastleCryptoUtilPublicKeyFactory_createKeyWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(keyInfo);
  }
  @catch (JavaLangRuntimeException *e) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_withJavaLangThrowable_(LibOrgBouncycastleCryptoTlsAlertDescription_unsupported_certificate, e);
  }
  if ([((LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *) nil_chk(self->serverPublicKey_)) isPrivate]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  self->rsaServerPublicKey_ = [self validateRSAPublicKeyWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:(LibOrgBouncycastleCryptoParamsRSAKeyParameters *) cast_chk(self->serverPublicKey_, [LibOrgBouncycastleCryptoParamsRSAKeyParameters class])];
  LibOrgBouncycastleCryptoTlsTlsUtils_validateKeyUsageWithLibOrgBouncycastleAsn1X509X509Certificate_withInt_(x509Cert, LibOrgBouncycastleAsn1X509KeyUsage_keyEncipherment);
  [super processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:serverCertificate];
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
  if (!([LibOrgBouncycastleCryptoTlsTlsSignerCredentials_class_() isInstance:clientCredentials])) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
}

- (void)generateClientKeyExchangeWithJavaIoOutputStream:(JavaIoOutputStream *)output {
  self->premasterSecret_ = LibOrgBouncycastleCryptoTlsTlsRSAUtils_generateEncryptedPreMasterSecretWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoParamsRSAKeyParameters_withJavaIoOutputStream_(context_, rsaServerPublicKey_, output);
}

- (void)processClientKeyExchangeWithJavaIoInputStream:(JavaIoInputStream *)input {
  IOSByteArray *encryptedPreMasterSecret;
  if (LibOrgBouncycastleCryptoTlsTlsUtils_isSSLWithLibOrgBouncycastleCryptoTlsTlsContext_(context_)) {
    encryptedPreMasterSecret = LibOrgBouncycastleUtilIoStreams_readAllWithJavaIoInputStream_(input);
  }
  else {
    encryptedPreMasterSecret = LibOrgBouncycastleCryptoTlsTlsUtils_readOpaque16WithJavaIoInputStream_(input);
  }
  self->premasterSecret_ = [((id<LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials>) nil_chk(serverCredentials_)) decryptPreMasterSecretWithByteArray:encryptedPreMasterSecret];
}

- (IOSByteArray *)generatePremasterSecret {
  if (self->premasterSecret_ == nil) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
  IOSByteArray *tmp = self->premasterSecret_;
  self->premasterSecret_ = nil;
  return tmp;
}

- (LibOrgBouncycastleCryptoParamsRSAKeyParameters *)validateRSAPublicKeyWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:(LibOrgBouncycastleCryptoParamsRSAKeyParameters *)key {
  if (![((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(key)) getExponent])) isProbablePrimeWithInt:2]) {
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_illegal_parameter);
  }
  return key;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 7, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 8, 3, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 9, 10, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 11, 12, 1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;", 0x4, 13, 14, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaUtilVector:);
  methods[1].selector = @selector(skipServerCredentials);
  methods[2].selector = @selector(processServerCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:);
  methods[3].selector = @selector(processServerCertificateWithLibOrgBouncycastleCryptoTlsCertificate:);
  methods[4].selector = @selector(validateCertificateRequestWithLibOrgBouncycastleCryptoTlsCertificateRequest:);
  methods[5].selector = @selector(processClientCredentialsWithLibOrgBouncycastleCryptoTlsTlsCredentials:);
  methods[6].selector = @selector(generateClientKeyExchangeWithJavaIoOutputStream:);
  methods[7].selector = @selector(processClientKeyExchangeWithJavaIoInputStream:);
  methods[8].selector = @selector(generatePremasterSecret);
  methods[9].selector = @selector(validateRSAPublicKeyWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serverPublicKey_", "LLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "rsaServerPublicKey_", "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "serverCredentials_", "LLibOrgBouncycastleCryptoTlsTlsEncryptionCredentials;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "premasterSecret_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaUtilVector;", "LJavaIoIOException;", "processServerCredentials", "LLibOrgBouncycastleCryptoTlsTlsCredentials;", "processServerCertificate", "LLibOrgBouncycastleCryptoTlsCertificate;", "validateCertificateRequest", "LLibOrgBouncycastleCryptoTlsCertificateRequest;", "processClientCredentials", "generateClientKeyExchange", "LJavaIoOutputStream;", "processClientKeyExchange", "LJavaIoInputStream;", "validateRSAPublicKey", "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange = { "TlsRSAKeyExchange", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 10, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange;
}

@end

void LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange_initWithJavaUtilVector_(LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange *self, JavaUtilVector *supportedSignatureAlgorithms) {
  LibOrgBouncycastleCryptoTlsAbstractTlsKeyExchange_initWithInt_withJavaUtilVector_(self, LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_RSA, supportedSignatureAlgorithms);
  self->serverPublicKey_ = nil;
  self->rsaServerPublicKey_ = nil;
  self->serverCredentials_ = nil;
}

LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange *new_LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange_initWithJavaUtilVector_(JavaUtilVector *supportedSignatureAlgorithms) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange, initWithJavaUtilVector_, supportedSignatureAlgorithms)
}

LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange *create_LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange_initWithJavaUtilVector_(JavaUtilVector *supportedSignatureAlgorithms) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange, initWithJavaUtilVector_, supportedSignatureAlgorithms)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsTlsRSAKeyExchange)