//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/ec/ECElGamalDecryptor.java
//

#include "CipherParameters.h"
#include "ECAlgorithms.h"
#include "ECCurve.h"
#include "ECDomainParameters.h"
#include "ECElGamalDecryptor.h"
#include "ECPair.h"
#include "ECPoint.h"
#include "ECPrivateKeyParameters.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleCryptoEcECElGamalDecryptor () {
 @public
  LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *key_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoEcECElGamalDecryptor, key_, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)

@implementation LibOrgBouncycastleCryptoEcECElGamalDecryptor

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoEcECElGamalDecryptor_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  if (!([param isKindOfClass:[LibOrgBouncycastleCryptoParamsECPrivateKeyParameters class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"ECPrivateKeyParameters are required for decryption.");
  }
  self->key_ = (LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) cast_chk(param, [LibOrgBouncycastleCryptoParamsECPrivateKeyParameters class]);
}

- (LibOrgBouncycastleMathEcECPoint *)decryptWithLibOrgBouncycastleCryptoEcECPair:(LibOrgBouncycastleCryptoEcECPair *)pair {
  if (key_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"ECElGamalDecryptor not initialised");
  }
  LibOrgBouncycastleMathEcECCurve *curve = [((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk([key_ getParameters])) getCurve];
  LibOrgBouncycastleMathEcECPoint *tmp = [((LibOrgBouncycastleMathEcECPoint *) nil_chk(LibOrgBouncycastleMathEcECAlgorithms_cleanPointWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_(curve, [((LibOrgBouncycastleCryptoEcECPair *) nil_chk(pair)) getX]))) multiplyWithJavaMathBigInteger:[((LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *) nil_chk(key_)) getD]];
  return [((LibOrgBouncycastleMathEcECPoint *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(LibOrgBouncycastleMathEcECAlgorithms_cleanPointWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_(curve, [pair getY]))) subtractWithLibOrgBouncycastleMathEcECPoint:tmp])) normalize];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(decryptWithLibOrgBouncycastleCryptoEcECPair:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "key_", "LLibOrgBouncycastleCryptoParamsECPrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LLibOrgBouncycastleCryptoCipherParameters;", "decrypt", "LLibOrgBouncycastleCryptoEcECPair;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoEcECElGamalDecryptor = { "ECElGamalDecryptor", "lib.org.bouncycastle.crypto.ec", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoEcECElGamalDecryptor;
}

@end

void LibOrgBouncycastleCryptoEcECElGamalDecryptor_init(LibOrgBouncycastleCryptoEcECElGamalDecryptor *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoEcECElGamalDecryptor *new_LibOrgBouncycastleCryptoEcECElGamalDecryptor_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoEcECElGamalDecryptor, init)
}

LibOrgBouncycastleCryptoEcECElGamalDecryptor *create_LibOrgBouncycastleCryptoEcECElGamalDecryptor_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoEcECElGamalDecryptor, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoEcECElGamalDecryptor)
