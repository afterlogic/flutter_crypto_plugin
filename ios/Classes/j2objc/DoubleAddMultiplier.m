//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/DoubleAddMultiplier.java
//

#include "AbstractECMultiplier.h"
#include "DoubleAddMultiplier.h"
#include "ECCurve.h"
#include "ECPoint.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleMathEcDoubleAddMultiplier

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcDoubleAddMultiplier_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleMathEcECPoint *)multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                                  withJavaMathBigInteger:(JavaMathBigInteger *)k {
  IOSObjectArray *R = [IOSObjectArray newArrayWithObjects:(id[]){ [((LibOrgBouncycastleMathEcECCurve *) nil_chk([((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) getCurve])) getInfinity], p } count:2 type:LibOrgBouncycastleMathEcECPoint_class_()];
  jint n = [((JavaMathBigInteger *) nil_chk(k)) bitLength];
  for (jint i = 0; i < n; ++i) {
    jint b = [k testBitWithInt:i] ? 1 : 0;
    jint bp = 1 - b;
    (void) IOSObjectArray_Set(R, bp, [((LibOrgBouncycastleMathEcECPoint *) nil_chk(IOSObjectArray_Get(R, bp))) twicePlusWithLibOrgBouncycastleMathEcECPoint:IOSObjectArray_Get(R, b)]);
  }
  return IOSObjectArray_Get(R, 0);
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
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcDoubleAddMultiplier = { "DoubleAddMultiplier", "lib.org.bouncycastle.math.ec", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcDoubleAddMultiplier;
}

@end

void LibOrgBouncycastleMathEcDoubleAddMultiplier_init(LibOrgBouncycastleMathEcDoubleAddMultiplier *self) {
  LibOrgBouncycastleMathEcAbstractECMultiplier_init(self);
}

LibOrgBouncycastleMathEcDoubleAddMultiplier *new_LibOrgBouncycastleMathEcDoubleAddMultiplier_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcDoubleAddMultiplier, init)
}

LibOrgBouncycastleMathEcDoubleAddMultiplier *create_LibOrgBouncycastleMathEcDoubleAddMultiplier_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcDoubleAddMultiplier, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcDoubleAddMultiplier)
