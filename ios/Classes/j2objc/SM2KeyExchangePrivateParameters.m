//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/SM2KeyExchangePrivateParameters.java
//

#include "ECDomainParameters.h"
#include "ECPoint.h"
#include "ECPrivateKeyParameters.h"
#include "J2ObjC_source.h"
#include "SM2KeyExchangePrivateParameters.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters () {
 @public
  jboolean initiator_;
  LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *staticPrivateKey_;
  LibOrgBouncycastleMathEcECPoint *staticPublicPoint_;
  LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *ephemeralPrivateKey_;
  LibOrgBouncycastleMathEcECPoint *ephemeralPublicPoint_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters, staticPrivateKey_, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters, staticPublicPoint_, LibOrgBouncycastleMathEcECPoint *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters, ephemeralPrivateKey_, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters, ephemeralPublicPoint_, LibOrgBouncycastleMathEcECPoint *)

@implementation LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters

- (instancetype)initWithBoolean:(jboolean)initiator
withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)staticPrivateKey
withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)ephemeralPrivateKey {
  LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(self, initiator, staticPrivateKey, ephemeralPrivateKey);
  return self;
}

- (jboolean)isInitiator {
  return initiator_;
}

- (LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)getStaticPrivateKey {
  return staticPrivateKey_;
}

- (LibOrgBouncycastleMathEcECPoint *)getStaticPublicPoint {
  return staticPublicPoint_;
}

- (LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)getEphemeralPrivateKey {
  return ephemeralPrivateKey_;
}

- (LibOrgBouncycastleMathEcECPoint *)getEphemeralPublicPoint {
  return ephemeralPublicPoint_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsECPrivateKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleCryptoParamsECPrivateKeyParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithBoolean:withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters:withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters:);
  methods[1].selector = @selector(isInitiator);
  methods[2].selector = @selector(getStaticPrivateKey);
  methods[3].selector = @selector(getStaticPublicPoint);
  methods[4].selector = @selector(getEphemeralPrivateKey);
  methods[5].selector = @selector(getEphemeralPublicPoint);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "initiator_", "Z", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "staticPrivateKey_", "LLibOrgBouncycastleCryptoParamsECPrivateKeyParameters;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "staticPublicPoint_", "LLibOrgBouncycastleMathEcECPoint;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "ephemeralPrivateKey_", "LLibOrgBouncycastleCryptoParamsECPrivateKeyParameters;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "ephemeralPublicPoint_", "LLibOrgBouncycastleMathEcECPoint;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "ZLLibOrgBouncycastleCryptoParamsECPrivateKeyParameters;LLibOrgBouncycastleCryptoParamsECPrivateKeyParameters;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters = { "SM2KeyExchangePrivateParameters", "lib.org.bouncycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 6, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters;
}

@end

void LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters *self, jboolean initiator, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *ephemeralPrivateKey) {
  NSObject_init(self);
  if (staticPrivateKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"staticPrivateKey cannot be null");
  }
  if (ephemeralPrivateKey == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"ephemeralPrivateKey cannot be null");
  }
  LibOrgBouncycastleCryptoParamsECDomainParameters *parameters = [staticPrivateKey getParameters];
  if (![((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(parameters)) isEqual:[ephemeralPrivateKey getParameters]]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Static and ephemeral private keys have different domain parameters");
  }
  self->initiator_ = initiator;
  self->staticPrivateKey_ = staticPrivateKey;
  self->staticPublicPoint_ = [((LibOrgBouncycastleMathEcECPoint *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk([parameters getG])) multiplyWithJavaMathBigInteger:[staticPrivateKey getD]])) normalize];
  self->ephemeralPrivateKey_ = ephemeralPrivateKey;
  self->ephemeralPublicPoint_ = [((LibOrgBouncycastleMathEcECPoint *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk([parameters getG])) multiplyWithJavaMathBigInteger:[ephemeralPrivateKey getD]])) normalize];
}

LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters *new_LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(jboolean initiator, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *ephemeralPrivateKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters, initWithBoolean_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_, initiator, staticPrivateKey, ephemeralPrivateKey)
}

LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters *create_LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters_initWithBoolean_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(jboolean initiator, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *staticPrivateKey, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *ephemeralPrivateKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters, initWithBoolean_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_, initiator, staticPrivateKey, ephemeralPrivateKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoParamsSM2KeyExchangePrivateParameters)
