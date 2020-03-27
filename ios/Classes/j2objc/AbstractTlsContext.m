//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/AbstractTlsContext.java
//

#include "AbstractTlsContext.h"
#include "Digest.h"
#include "DigestRandomGenerator.h"
#include "HashAlgorithm.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ProtocolVersion.h"
#include "RandomGenerator.h"
#include "SecurityParameters.h"
#include "Times.h"
#include "TlsSession.h"
#include "TlsUtils.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"

#pragma clang diagnostic ignored "-Wprotocol"

@interface LibOrgBouncycastleCryptoTlsAbstractTlsContext () {
 @public
  id<LibOrgBouncycastleCryptoPrngRandomGenerator> nonceRandom_;
  JavaSecuritySecureRandom *secureRandom_;
  LibOrgBouncycastleCryptoTlsSecurityParameters *securityParameters_;
  LibOrgBouncycastleCryptoTlsProtocolVersion *clientVersion_;
  LibOrgBouncycastleCryptoTlsProtocolVersion *serverVersion_;
  id<LibOrgBouncycastleCryptoTlsTlsSession> session_;
  id userObject_;
}

+ (jlong)nextCounterValue;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsContext, nonceRandom_, id<LibOrgBouncycastleCryptoPrngRandomGenerator>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsContext, secureRandom_, JavaSecuritySecureRandom *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsContext, securityParameters_, LibOrgBouncycastleCryptoTlsSecurityParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsContext, clientVersion_, LibOrgBouncycastleCryptoTlsProtocolVersion *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsContext, serverVersion_, LibOrgBouncycastleCryptoTlsProtocolVersion *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsContext, session_, id<LibOrgBouncycastleCryptoTlsTlsSession>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsAbstractTlsContext, userObject_, id)

inline jlong LibOrgBouncycastleCryptoTlsAbstractTlsContext_get_counter(void);
inline jlong LibOrgBouncycastleCryptoTlsAbstractTlsContext_set_counter(jlong value);
inline jlong *LibOrgBouncycastleCryptoTlsAbstractTlsContext_getRef_counter(void);
static jlong LibOrgBouncycastleCryptoTlsAbstractTlsContext_counter;
J2OBJC_STATIC_FIELD_PRIMITIVE(LibOrgBouncycastleCryptoTlsAbstractTlsContext, counter, jlong)

__attribute__((unused)) static jlong LibOrgBouncycastleCryptoTlsAbstractTlsContext_nextCounterValue(void);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoTlsAbstractTlsContext)

@implementation LibOrgBouncycastleCryptoTlsAbstractTlsContext

+ (jlong)nextCounterValue {
  return LibOrgBouncycastleCryptoTlsAbstractTlsContext_nextCounterValue();
}

- (instancetype)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)secureRandom
withLibOrgBouncycastleCryptoTlsSecurityParameters:(LibOrgBouncycastleCryptoTlsSecurityParameters *)securityParameters {
  LibOrgBouncycastleCryptoTlsAbstractTlsContext_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoTlsSecurityParameters_(self, secureRandom, securityParameters);
  return self;
}

- (id<LibOrgBouncycastleCryptoPrngRandomGenerator>)getNonceRandomGenerator {
  return nonceRandom_;
}

- (JavaSecuritySecureRandom *)getSecureRandom {
  return secureRandom_;
}

- (LibOrgBouncycastleCryptoTlsSecurityParameters *)getSecurityParameters {
  return securityParameters_;
}

- (LibOrgBouncycastleCryptoTlsProtocolVersion *)getClientVersion {
  return clientVersion_;
}

- (void)setClientVersionWithLibOrgBouncycastleCryptoTlsProtocolVersion:(LibOrgBouncycastleCryptoTlsProtocolVersion *)clientVersion {
  self->clientVersion_ = clientVersion;
}

- (LibOrgBouncycastleCryptoTlsProtocolVersion *)getServerVersion {
  return serverVersion_;
}

- (void)setServerVersionWithLibOrgBouncycastleCryptoTlsProtocolVersion:(LibOrgBouncycastleCryptoTlsProtocolVersion *)serverVersion {
  self->serverVersion_ = serverVersion;
}

- (id<LibOrgBouncycastleCryptoTlsTlsSession>)getResumableSession {
  return session_;
}

- (void)setResumableSessionWithLibOrgBouncycastleCryptoTlsTlsSession:(id<LibOrgBouncycastleCryptoTlsTlsSession>)session {
  self->session_ = session;
}

- (id)getUserObject {
  return userObject_;
}

- (void)setUserObjectWithId:(id)userObject {
  self->userObject_ = userObject;
}

- (IOSByteArray *)exportKeyingMaterialWithNSString:(NSString *)asciiLabel
                                     withByteArray:(IOSByteArray *)context_value
                                           withInt:(jint)length {
  if (context_value != nil && !LibOrgBouncycastleCryptoTlsTlsUtils_isValidUint16WithInt_(context_value->size_)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'context_value' must have length less than 2^16 (or be null)");
  }
  LibOrgBouncycastleCryptoTlsSecurityParameters *sp = [self getSecurityParameters];
  if (![((LibOrgBouncycastleCryptoTlsSecurityParameters *) nil_chk(sp)) isExtendedMasterSecret]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"cannot export keying material without extended_master_secret");
  }
  IOSByteArray *cr = [sp getClientRandom];
  IOSByteArray *sr = [sp getServerRandom];
  jint seedLength = ((IOSByteArray *) nil_chk(cr))->size_ + ((IOSByteArray *) nil_chk(sr))->size_;
  if (context_value != nil) {
    seedLength += (2 + context_value->size_);
  }
  IOSByteArray *seed = [IOSByteArray newArrayWithLength:seedLength];
  jint seedPos = 0;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(cr, 0, seed, seedPos, cr->size_);
  seedPos += cr->size_;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(sr, 0, seed, seedPos, sr->size_);
  seedPos += sr->size_;
  if (context_value != nil) {
    LibOrgBouncycastleCryptoTlsTlsUtils_writeUint16WithInt_withByteArray_withInt_(context_value->size_, seed, seedPos);
    seedPos += 2;
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(context_value, 0, seed, seedPos, context_value->size_);
    seedPos += context_value->size_;
  }
  if (seedPos != seedLength) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"error in calculation of seed for export");
  }
  return LibOrgBouncycastleCryptoTlsTlsUtils_PRFWithLibOrgBouncycastleCryptoTlsTlsContext_withByteArray_withNSString_withByteArray_withInt_(self, [sp getMasterSecret], asciiLabel, seed, length);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "J", 0x2a, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoPrngRandomGenerator;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySecureRandom;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsSecurityParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsProtocolVersion;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 1, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsProtocolVersion;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 3, 2, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoTlsTlsSession;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 4, 5, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 8, 9, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(nextCounterValue);
  methods[1].selector = @selector(initWithJavaSecuritySecureRandom:withLibOrgBouncycastleCryptoTlsSecurityParameters:);
  methods[2].selector = @selector(getNonceRandomGenerator);
  methods[3].selector = @selector(getSecureRandom);
  methods[4].selector = @selector(getSecurityParameters);
  methods[5].selector = @selector(getClientVersion);
  methods[6].selector = @selector(setClientVersionWithLibOrgBouncycastleCryptoTlsProtocolVersion:);
  methods[7].selector = @selector(getServerVersion);
  methods[8].selector = @selector(setServerVersionWithLibOrgBouncycastleCryptoTlsProtocolVersion:);
  methods[9].selector = @selector(getResumableSession);
  methods[10].selector = @selector(setResumableSessionWithLibOrgBouncycastleCryptoTlsTlsSession:);
  methods[11].selector = @selector(getUserObject);
  methods[12].selector = @selector(setUserObjectWithId:);
  methods[13].selector = @selector(exportKeyingMaterialWithNSString:withByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "counter", "J", .constantValue.asLong = 0, 0xa, -1, 10, -1, -1 },
    { "nonceRandom_", "LLibOrgBouncycastleCryptoPrngRandomGenerator;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "secureRandom_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "securityParameters_", "LLibOrgBouncycastleCryptoTlsSecurityParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "clientVersion_", "LLibOrgBouncycastleCryptoTlsProtocolVersion;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "serverVersion_", "LLibOrgBouncycastleCryptoTlsProtocolVersion;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "session_", "LLibOrgBouncycastleCryptoTlsTlsSession;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "userObject_", "LNSObject;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecuritySecureRandom;LLibOrgBouncycastleCryptoTlsSecurityParameters;", "setClientVersion", "LLibOrgBouncycastleCryptoTlsProtocolVersion;", "setServerVersion", "setResumableSession", "LLibOrgBouncycastleCryptoTlsTlsSession;", "setUserObject", "LNSObject;", "exportKeyingMaterial", "LNSString;[BI", &LibOrgBouncycastleCryptoTlsAbstractTlsContext_counter };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoTlsAbstractTlsContext = { "AbstractTlsContext", "lib.org.bouncycastle.crypto.tls", ptrTable, methods, fields, 7, 0x400, 14, 8, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoTlsAbstractTlsContext;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoTlsAbstractTlsContext class]) {
    LibOrgBouncycastleCryptoTlsAbstractTlsContext_counter = LibOrgBouncycastleUtilTimes_nanoTime();
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoTlsAbstractTlsContext)
  }
}

@end

jlong LibOrgBouncycastleCryptoTlsAbstractTlsContext_nextCounterValue() {
  LibOrgBouncycastleCryptoTlsAbstractTlsContext_initialize();
  @synchronized(LibOrgBouncycastleCryptoTlsAbstractTlsContext_class_()) {
    return ++LibOrgBouncycastleCryptoTlsAbstractTlsContext_counter;
  }
}

void LibOrgBouncycastleCryptoTlsAbstractTlsContext_initWithJavaSecuritySecureRandom_withLibOrgBouncycastleCryptoTlsSecurityParameters_(LibOrgBouncycastleCryptoTlsAbstractTlsContext *self, JavaSecuritySecureRandom *secureRandom, LibOrgBouncycastleCryptoTlsSecurityParameters *securityParameters) {
  NSObject_init(self);
  self->clientVersion_ = nil;
  self->serverVersion_ = nil;
  self->session_ = nil;
  self->userObject_ = nil;
  id<LibOrgBouncycastleCryptoDigest> d = LibOrgBouncycastleCryptoTlsTlsUtils_createHashWithShort_(LibOrgBouncycastleCryptoTlsHashAlgorithm_sha256);
  IOSByteArray *seed = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(d)) getDigestSize]];
  [((JavaSecuritySecureRandom *) nil_chk(secureRandom)) nextBytesWithByteArray:seed];
  self->nonceRandom_ = new_LibOrgBouncycastleCryptoPrngDigestRandomGenerator_initWithLibOrgBouncycastleCryptoDigest_(d);
  [self->nonceRandom_ addSeedMaterialWithLong:LibOrgBouncycastleCryptoTlsAbstractTlsContext_nextCounterValue()];
  [((id<LibOrgBouncycastleCryptoPrngRandomGenerator>) nil_chk(self->nonceRandom_)) addSeedMaterialWithLong:LibOrgBouncycastleUtilTimes_nanoTime()];
  [((id<LibOrgBouncycastleCryptoPrngRandomGenerator>) nil_chk(self->nonceRandom_)) addSeedMaterialWithByteArray:seed];
  self->secureRandom_ = secureRandom;
  self->securityParameters_ = securityParameters;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoTlsAbstractTlsContext)