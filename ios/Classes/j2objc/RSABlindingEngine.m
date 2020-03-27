//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/RSABlindingEngine.java
//

#include "CipherParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ParametersWithRandom.h"
#include "RSABlindingEngine.h"
#include "RSABlindingParameters.h"
#include "RSACoreEngine.h"
#include "RSAKeyParameters.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoEnginesRSABlindingEngine () {
 @public
  LibOrgBouncycastleCryptoEnginesRSACoreEngine *core_;
  LibOrgBouncycastleCryptoParamsRSAKeyParameters *key_;
  JavaMathBigInteger *blindingFactor_;
  jboolean forEncryption_;
}

- (JavaMathBigInteger *)blindMessageWithJavaMathBigInteger:(JavaMathBigInteger *)msg;

- (JavaMathBigInteger *)unblindMessageWithJavaMathBigInteger:(JavaMathBigInteger *)blindedMsg;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesRSABlindingEngine, core_, LibOrgBouncycastleCryptoEnginesRSACoreEngine *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesRSABlindingEngine, key_, LibOrgBouncycastleCryptoParamsRSAKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEnginesRSABlindingEngine, blindingFactor_, JavaMathBigInteger *)

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoEnginesRSABlindingEngine_blindMessageWithJavaMathBigInteger_(LibOrgBouncycastleCryptoEnginesRSABlindingEngine *self, JavaMathBigInteger *msg);

__attribute__((unused)) static JavaMathBigInteger *LibOrgBouncycastleCryptoEnginesRSABlindingEngine_unblindMessageWithJavaMathBigInteger_(LibOrgBouncycastleCryptoEnginesRSABlindingEngine *self, JavaMathBigInteger *blindedMsg);

@implementation LibOrgBouncycastleCryptoEnginesRSABlindingEngine

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEnginesRSABlindingEngine_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  LibOrgBouncycastleCryptoParamsRSABlindingParameters *p;
  if ([param isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithRandom class]]) {
    LibOrgBouncycastleCryptoParamsParametersWithRandom *rParam = (LibOrgBouncycastleCryptoParamsParametersWithRandom *) param;
    p = (LibOrgBouncycastleCryptoParamsRSABlindingParameters *) cast_chk([((LibOrgBouncycastleCryptoParamsParametersWithRandom *) nil_chk(rParam)) getParameters], [LibOrgBouncycastleCryptoParamsRSABlindingParameters class]);
  }
  else {
    p = (LibOrgBouncycastleCryptoParamsRSABlindingParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsRSABlindingParameters class]);
  }
  [((LibOrgBouncycastleCryptoEnginesRSACoreEngine *) nil_chk(core_)) init__WithBoolean:forEncryption withLibOrgBouncycastleCryptoCipherParameters:[((LibOrgBouncycastleCryptoParamsRSABlindingParameters *) nil_chk(p)) getPublicKey]];
  self->forEncryption_ = forEncryption;
  self->key_ = [p getPublicKey];
  self->blindingFactor_ = [p getBlindingFactor];
}

- (jint)getInputBlockSize {
  return [((LibOrgBouncycastleCryptoEnginesRSACoreEngine *) nil_chk(core_)) getInputBlockSize];
}

- (jint)getOutputBlockSize {
  return [((LibOrgBouncycastleCryptoEnginesRSACoreEngine *) nil_chk(core_)) getOutputBlockSize];
}

- (IOSByteArray *)processBlockWithByteArray:(IOSByteArray *)inArg
                                    withInt:(jint)inOff
                                    withInt:(jint)inLen {
  JavaMathBigInteger *msg = [((LibOrgBouncycastleCryptoEnginesRSACoreEngine *) nil_chk(core_)) convertInputWithByteArray:inArg withInt:inOff withInt:inLen];
  if (forEncryption_) {
    msg = LibOrgBouncycastleCryptoEnginesRSABlindingEngine_blindMessageWithJavaMathBigInteger_(self, msg);
  }
  else {
    msg = LibOrgBouncycastleCryptoEnginesRSABlindingEngine_unblindMessageWithJavaMathBigInteger_(self, msg);
  }
  return [((LibOrgBouncycastleCryptoEnginesRSACoreEngine *) nil_chk(core_)) convertOutputWithJavaMathBigInteger:msg];
}

- (JavaMathBigInteger *)blindMessageWithJavaMathBigInteger:(JavaMathBigInteger *)msg {
  return LibOrgBouncycastleCryptoEnginesRSABlindingEngine_blindMessageWithJavaMathBigInteger_(self, msg);
}

- (JavaMathBigInteger *)unblindMessageWithJavaMathBigInteger:(JavaMathBigInteger *)blindedMsg {
  return LibOrgBouncycastleCryptoEnginesRSABlindingEngine_unblindMessageWithJavaMathBigInteger_(self, blindedMsg);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, 4, 5, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x2, 6, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(getInputBlockSize);
  methods[3].selector = @selector(getOutputBlockSize);
  methods[4].selector = @selector(processBlockWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(blindMessageWithJavaMathBigInteger:);
  methods[6].selector = @selector(unblindMessageWithJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "core_", "LLibOrgBouncycastleCryptoEnginesRSACoreEngine;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "key_", "LLibOrgBouncycastleCryptoParamsRSAKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "blindingFactor_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "forEncryption_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "processBlock", "[BII", "blindMessage", "LJavaMathBigInteger;", "unblindMessage" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEnginesRSABlindingEngine = { "RSABlindingEngine", "lib.org.bouncycastle.crypto.engines", ptrTable, methods, fields, 7, 0x1, 7, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEnginesRSABlindingEngine;
}

@end

void LibOrgBouncycastleCryptoEnginesRSABlindingEngine_init(LibOrgBouncycastleCryptoEnginesRSABlindingEngine *self) {
  NSObject_init(self);
  self->core_ = new_LibOrgBouncycastleCryptoEnginesRSACoreEngine_init();
}

LibOrgBouncycastleCryptoEnginesRSABlindingEngine *new_LibOrgBouncycastleCryptoEnginesRSABlindingEngine_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEnginesRSABlindingEngine, init)
}

LibOrgBouncycastleCryptoEnginesRSABlindingEngine *create_LibOrgBouncycastleCryptoEnginesRSABlindingEngine_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEnginesRSABlindingEngine, init)
}

JavaMathBigInteger *LibOrgBouncycastleCryptoEnginesRSABlindingEngine_blindMessageWithJavaMathBigInteger_(LibOrgBouncycastleCryptoEnginesRSABlindingEngine *self, JavaMathBigInteger *msg) {
  JavaMathBigInteger *blindMsg = self->blindingFactor_;
  blindMsg = [((JavaMathBigInteger *) nil_chk(msg)) multiplyWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(blindMsg)) modPowWithJavaMathBigInteger:[((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(self->key_)) getExponent] withJavaMathBigInteger:[((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(self->key_)) getModulus]]];
  blindMsg = [((JavaMathBigInteger *) nil_chk(blindMsg)) modWithJavaMathBigInteger:[((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(self->key_)) getModulus]];
  return blindMsg;
}

JavaMathBigInteger *LibOrgBouncycastleCryptoEnginesRSABlindingEngine_unblindMessageWithJavaMathBigInteger_(LibOrgBouncycastleCryptoEnginesRSABlindingEngine *self, JavaMathBigInteger *blindedMsg) {
  JavaMathBigInteger *m = [((LibOrgBouncycastleCryptoParamsRSAKeyParameters *) nil_chk(self->key_)) getModulus];
  JavaMathBigInteger *msg = blindedMsg;
  JavaMathBigInteger *blindFactorInverse = [((JavaMathBigInteger *) nil_chk(self->blindingFactor_)) modInverseWithJavaMathBigInteger:m];
  msg = [((JavaMathBigInteger *) nil_chk(msg)) multiplyWithJavaMathBigInteger:blindFactorInverse];
  msg = [((JavaMathBigInteger *) nil_chk(msg)) modWithJavaMathBigInteger:m];
  return msg;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEnginesRSABlindingEngine)