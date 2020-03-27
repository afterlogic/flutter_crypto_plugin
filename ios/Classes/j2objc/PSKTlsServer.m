//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/PSKTlsServer.java
//

#include "AbstractTlsServer.h"
#include "AlertDescription.h"
#include "CipherSuite.h"
#include "DHParameters.h"
#include "DHStandardGroups.h"
#include "DefaultTlsCipherFactory.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyExchangeAlgorithm.h"
#include "PSKTlsServer.h"
#include "TlsCipherFactory.h"
#include "TlsCredentials.h"
#include "TlsEncryptionCredentials.h"
#include "TlsFatalAlert.h"
#include "TlsKeyExchange.h"
#include "TlsPSKIdentityManager.h"
#include "TlsPSKKeyExchange.h"
#include "TlsUtils.h"
#include "java/util/Vector.h"

@implementation LibOrgBouncycastleCryptoTlsPSKTlsServer

- (instancetype)initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager:(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager>)pskIdentityManager {
  LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(self, pskIdentityManager);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory:(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory>)cipherFactory
               withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager:(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager>)pskIdentityManager {
  LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(self, cipherFactory, pskIdentityManager);
  return self;
}

- (id<LibOrgBouncycastleCryptoTlsTlsEncryptionCredentials>)getRSAEncryptionCredentials {
  @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
}

- (LibOrgBouncycastleCryptoParamsDHParameters *)getDHParameters {
  return JreLoadStatic(LibOrgBouncycastleCryptoAgreementDHStandardGroups, rfc7919_ffdhe2048);
}

- (IOSIntArray *)getCipherSuites {
  return [IOSIntArray newArrayWithInts:(jint[]){ LibOrgBouncycastleCryptoTlsCipherSuite_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, LibOrgBouncycastleCryptoTlsCipherSuite_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, LibOrgBouncycastleCryptoTlsCipherSuite_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, LibOrgBouncycastleCryptoTlsCipherSuite_TLS_DHE_PSK_WITH_AES_128_CBC_SHA } count:4];
}

- (id<LibOrgBouncycastleCryptoTlsTlsCredentials>)getCredentials {
  jint keyExchangeAlgorithm = LibOrgBouncycastleCryptoTlsTlsUtils_getKeyExchangeAlgorithmWithInt_(selectedCipherSuite_);
  switch (keyExchangeAlgorithm) {
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_DHE_PSK:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_PSK:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_PSK:
    return nil;
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_RSA_PSK:
    return [self getRSAEncryptionCredentials];
    default:
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
}

- (id<LibOrgBouncycastleCryptoTlsTlsKeyExchange>)getKeyExchange {
  jint keyExchangeAlgorithm = LibOrgBouncycastleCryptoTlsTlsUtils_getKeyExchangeAlgorithmWithInt_(selectedCipherSuite_);
  switch (keyExchangeAlgorithm) {
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_DHE_PSK:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_ECDHE_PSK:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_PSK:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_RSA_PSK:
    return [self createPSKKeyExchangeWithInt:keyExchangeAlgorithm];
    default:
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
}

- (id<LibOrgBouncycastleCryptoTlsTlsKeyExchange>)createPSKKeyExchangeWithInt:(jint)keyExchange {
  return new_LibOrgBouncycastleCryptoTlsTlsPSKKeyExchange_initWithInt_withJavaUtilVector_withLibOrgBouncycastleCryptoTlsTlsPSKIdentity_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_withLibOrgBouncycastleCryptoTlsTlsDHVerifier_withLibOrgBouncycastleCryptoParamsDHParameters_withIntArray_withShortArray_withShortArray_(keyExchange, supportedSignatureAlgorithms_, nil, pskIdentityManager_, nil, [self getDHParameters], namedCurves_, clientECPointFormats_, serverECPointFormats_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsEncryptionCredentials;", 0x4, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsDHParameters;", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsCredentials;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsKeyExchange;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsKeyExchange;", 0x4, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory:withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager:);
  methods[2].selector = @selector(getRSAEncryptionCredentials);
  methods[3].selector = @selector(getDHParameters);
  methods[4].selector = @selector(getCipherSuites);
  methods[5].selector = @selector(getCredentials);
  methods[6].selector = @selector(getKeyExchange);
  methods[7].selector = @selector(createPSKKeyExchangeWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "pskIdentityManager_", "LLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager;", "LLibOrgBouncycastleCryptoTlsTlsCipherFactory;LLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager;", "LJavaIoIOException;", "createPSKKeyExchange", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsPSKTlsServer = { "PSKTlsServer", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 8, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsPSKTlsServer;
}

@end

void LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(LibOrgBouncycastleCryptoTlsPSKTlsServer *self, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager) {
  LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(self, new_LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory_init(), pskIdentityManager);
}

LibOrgBouncycastleCryptoTlsPSKTlsServer *new_LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsPSKTlsServer, initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_, pskIdentityManager)
}

LibOrgBouncycastleCryptoTlsPSKTlsServer *create_LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsPSKTlsServer, initWithLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_, pskIdentityManager)
}

void LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(LibOrgBouncycastleCryptoTlsPSKTlsServer *self, id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager) {
  LibOrgBouncycastleCryptoTlsAbstractTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_(self, cipherFactory);
  self->pskIdentityManager_ = pskIdentityManager;
}

LibOrgBouncycastleCryptoTlsPSKTlsServer *new_LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsPSKTlsServer, initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_, cipherFactory, pskIdentityManager)
}

LibOrgBouncycastleCryptoTlsPSKTlsServer *create_LibOrgBouncycastleCryptoTlsPSKTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory, id<LibOrgBouncycastleCryptoTlsTlsPSKIdentityManager> pskIdentityManager) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsPSKTlsServer, initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsPSKIdentityManager_, cipherFactory, pskIdentityManager)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsPSKTlsServer)
