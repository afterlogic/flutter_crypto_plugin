//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/SRPTlsServer.java
//

#include "AbstractTlsServer.h"
#include "AlertDescription.h"
#include "CipherSuite.h"
#include "DefaultTlsCipherFactory.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyExchangeAlgorithm.h"
#include "SRPTlsServer.h"
#include "TlsCipherFactory.h"
#include "TlsCredentials.h"
#include "TlsFatalAlert.h"
#include "TlsKeyExchange.h"
#include "TlsSRPIdentityManager.h"
#include "TlsSRPKeyExchange.h"
#include "TlsSRPLoginParameters.h"
#include "TlsSRPUtils.h"
#include "TlsSignerCredentials.h"
#include "TlsUtils.h"
#include "java/util/Hashtable.h"
#include "java/util/Vector.h"

@implementation LibOrgBouncycastleCryptoTlsSRPTlsServer

- (instancetype)initWithLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager:(id<LibOrgBouncycastleCryptoTlsTlsSRPIdentityManager>)srpIdentityManager {
  LibOrgBouncycastleCryptoTlsSRPTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_(self, srpIdentityManager);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory:(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory>)cipherFactory
               withLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager:(id<LibOrgBouncycastleCryptoTlsTlsSRPIdentityManager>)srpIdentityManager {
  LibOrgBouncycastleCryptoTlsSRPTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_(self, cipherFactory, srpIdentityManager);
  return self;
}

- (id<LibOrgBouncycastleCryptoTlsTlsSignerCredentials>)getDSASignerCredentials {
  @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
}

- (id<LibOrgBouncycastleCryptoTlsTlsSignerCredentials>)getRSASignerCredentials {
  @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
}

- (IOSIntArray *)getCipherSuites {
  return [IOSIntArray newArrayWithInts:(jint[]){ LibOrgBouncycastleCryptoTlsCipherSuite_TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA, LibOrgBouncycastleCryptoTlsCipherSuite_TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA, LibOrgBouncycastleCryptoTlsCipherSuite_TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA, LibOrgBouncycastleCryptoTlsCipherSuite_TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA, LibOrgBouncycastleCryptoTlsCipherSuite_TLS_SRP_SHA_WITH_AES_256_CBC_SHA, LibOrgBouncycastleCryptoTlsCipherSuite_TLS_SRP_SHA_WITH_AES_128_CBC_SHA } count:6];
}

- (void)processClientExtensionsWithJavaUtilHashtable:(JavaUtilHashtable *)clientExtensions {
  [super processClientExtensionsWithJavaUtilHashtable:clientExtensions];
  self->srpIdentity_ = LibOrgBouncycastleCryptoTlsTlsSRPUtils_getSRPExtensionWithJavaUtilHashtable_(clientExtensions);
}

- (jint)getSelectedCipherSuite {
  jint cipherSuite = [super getSelectedCipherSuite];
  if (LibOrgBouncycastleCryptoTlsTlsSRPUtils_isSRPCipherSuiteWithInt_(cipherSuite)) {
    if (srpIdentity_ != nil) {
      self->loginParameters_ = [((id<LibOrgBouncycastleCryptoTlsTlsSRPIdentityManager>) nil_chk(srpIdentityManager_)) getLoginParametersWithByteArray:srpIdentity_];
    }
    if (loginParameters_ == nil) {
      @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_unknown_psk_identity);
    }
  }
  return cipherSuite;
}

- (id<LibOrgBouncycastleCryptoTlsTlsCredentials>)getCredentials {
  jint keyExchangeAlgorithm = LibOrgBouncycastleCryptoTlsTlsUtils_getKeyExchangeAlgorithmWithInt_(selectedCipherSuite_);
  switch (keyExchangeAlgorithm) {
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_SRP:
    return nil;
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_SRP_DSS:
    return [self getDSASignerCredentials];
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_SRP_RSA:
    return [self getRSASignerCredentials];
    default:
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
}

- (id<LibOrgBouncycastleCryptoTlsTlsKeyExchange>)getKeyExchange {
  jint keyExchangeAlgorithm = LibOrgBouncycastleCryptoTlsTlsUtils_getKeyExchangeAlgorithmWithInt_(selectedCipherSuite_);
  switch (keyExchangeAlgorithm) {
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_SRP:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_SRP_DSS:
    case LibOrgBouncycastleCryptoTlsKeyExchangeAlgorithm_SRP_RSA:
    return [self createSRPKeyExchangeWithInt:keyExchangeAlgorithm];
    default:
    @throw new_LibOrgBouncycastleCryptoTlsTlsFatalAlert_initWithShort_(LibOrgBouncycastleCryptoTlsAlertDescription_internal_error);
  }
}

- (id<LibOrgBouncycastleCryptoTlsTlsKeyExchange>)createSRPKeyExchangeWithInt:(jint)keyExchange {
  return new_LibOrgBouncycastleCryptoTlsTlsSRPKeyExchange_initWithInt_withJavaUtilVector_withByteArray_withLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters_(keyExchange, supportedSignatureAlgorithms_, srpIdentity_, loginParameters_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsSignerCredentials;", 0x4, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsSignerCredentials;", 0x4, -1, -1, 2, -1, -1, -1 },
    { NULL, "[I", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 2, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsCredentials;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsKeyExchange;", 0x1, -1, -1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsKeyExchange;", 0x4, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory:withLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager:);
  methods[2].selector = @selector(getDSASignerCredentials);
  methods[3].selector = @selector(getRSASignerCredentials);
  methods[4].selector = @selector(getCipherSuites);
  methods[5].selector = @selector(processClientExtensionsWithJavaUtilHashtable:);
  methods[6].selector = @selector(getSelectedCipherSuite);
  methods[7].selector = @selector(getCredentials);
  methods[8].selector = @selector(getKeyExchange);
  methods[9].selector = @selector(createSRPKeyExchangeWithInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "srpIdentityManager_", "LLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "srpIdentity_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "loginParameters_", "LLibOrgBouncycastleCryptoTlsTlsSRPLoginParameters;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager;", "LLibOrgBouncycastleCryptoTlsTlsCipherFactory;LLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager;", "LJavaIoIOException;", "processClientExtensions", "LJavaUtilHashtable;", "createSRPKeyExchange", "I" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsSRPTlsServer = { "SRPTlsServer", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 10, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsSRPTlsServer;
}

@end

void LibOrgBouncycastleCryptoTlsSRPTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_(LibOrgBouncycastleCryptoTlsSRPTlsServer *self, id<LibOrgBouncycastleCryptoTlsTlsSRPIdentityManager> srpIdentityManager) {
  LibOrgBouncycastleCryptoTlsSRPTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_(self, new_LibOrgBouncycastleCryptoTlsDefaultTlsCipherFactory_init(), srpIdentityManager);
}

LibOrgBouncycastleCryptoTlsSRPTlsServer *new_LibOrgBouncycastleCryptoTlsSRPTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsSRPIdentityManager> srpIdentityManager) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsSRPTlsServer, initWithLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_, srpIdentityManager)
}

LibOrgBouncycastleCryptoTlsSRPTlsServer *create_LibOrgBouncycastleCryptoTlsSRPTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsSRPIdentityManager> srpIdentityManager) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsSRPTlsServer, initWithLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_, srpIdentityManager)
}

void LibOrgBouncycastleCryptoTlsSRPTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_(LibOrgBouncycastleCryptoTlsSRPTlsServer *self, id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory, id<LibOrgBouncycastleCryptoTlsTlsSRPIdentityManager> srpIdentityManager) {
  LibOrgBouncycastleCryptoTlsAbstractTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_(self, cipherFactory);
  self->srpIdentity_ = nil;
  self->loginParameters_ = nil;
  self->srpIdentityManager_ = srpIdentityManager;
}

LibOrgBouncycastleCryptoTlsSRPTlsServer *new_LibOrgBouncycastleCryptoTlsSRPTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory, id<LibOrgBouncycastleCryptoTlsTlsSRPIdentityManager> srpIdentityManager) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoTlsSRPTlsServer, initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_, cipherFactory, srpIdentityManager)
}

LibOrgBouncycastleCryptoTlsSRPTlsServer *create_LibOrgBouncycastleCryptoTlsSRPTlsServer_initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_(id<LibOrgBouncycastleCryptoTlsTlsCipherFactory> cipherFactory, id<LibOrgBouncycastleCryptoTlsTlsSRPIdentityManager> srpIdentityManager) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoTlsSRPTlsServer, initWithLibOrgBouncycastleCryptoTlsTlsCipherFactory_withLibOrgBouncycastleCryptoTlsTlsSRPIdentityManager_, cipherFactory, srpIdentityManager)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsSRPTlsServer)
