//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/NafR2LMultiplier.java
//

#include "AbstractECMultiplier.h"
#include "ECCurve.h"
#include "ECPoint.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "NafR2LMultiplier.h"
#include "WNafUtil.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleMathEcNafR2LMultiplier

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcNafR2LMultiplier_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleMathEcECPoint *)multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                                  withJavaMathBigInteger:(JavaMathBigInteger *)k {
  IOSIntArray *naf = LibOrgBouncycastleMathEcWNafUtil_generateCompactNafWithJavaMathBigInteger_(k);
  LibOrgBouncycastleMathEcECPoint *R0 = [((LibOrgBouncycastleMathEcECCurve *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) getCurve])) getInfinity];
  LibOrgBouncycastleMathEcECPoint *R1 = p;
  jint zeroes = 0;
  for (jint i = 0; i < ((IOSIntArray *) nil_chk(naf))->size_; ++i) {
    jint ni = IOSIntArray_Get(naf, i);
    jint digit = JreRShift32(ni, 16);
    zeroes += ni & (jint) 0xFFFF;
    R1 = [((LibOrgBouncycastleMathEcECPoint *) nil_chk(R1)) timesPow2WithInt:zeroes];
    R0 = [((LibOrgBouncycastleMathEcECPoint *) nil_chk(R0)) addWithLibOrgBouncycastleMathEcECPoint:digit < 0 ? [((LibOrgBouncycastleMathEcECPoint *) nil_chk(R1)) negate] : R1];
    zeroes = 1;
  }
  return R0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "multiplyPositive", "LLibOrgBouncycastleMathEcECPoint;LJavaMathBigInteger;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcNafR2LMultiplier = { "NafR2LMultiplier", "lib.org.bouncycastle.math.ec", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcNafR2LMultiplier;
}

@end

void LibOrgBouncycastleMathEcNafR2LMultiplier_init(LibOrgBouncycastleMathEcNafR2LMultiplier *self) {
  LibOrgBouncycastleMathEcAbstractECMultiplier_init(self);
}

LibOrgBouncycastleMathEcNafR2LMultiplier *new_LibOrgBouncycastleMathEcNafR2LMultiplier_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcNafR2LMultiplier, init)
}

LibOrgBouncycastleMathEcNafR2LMultiplier *create_LibOrgBouncycastleMathEcNafR2LMultiplier_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcNafR2LMultiplier, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcNafR2LMultiplier)