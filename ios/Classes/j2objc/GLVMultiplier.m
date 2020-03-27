//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/GLVMultiplier.java
//

#include "AbstractECMultiplier.h"
#include "ECAlgorithms.h"
#include "ECCurve.h"
#include "ECPoint.h"
#include "ECPointMap.h"
#include "GLVEndomorphism.h"
#include "GLVMultiplier.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"

@implementation LibOrgBouncycastleMathEcGLVMultiplier

- (instancetype)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
        withLibOrgBouncycastleMathEcEndoGLVEndomorphism:(id<LibOrgBouncycastleMathEcEndoGLVEndomorphism>)glvEndomorphism {
  LibOrgBouncycastleMathEcGLVMultiplier_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcEndoGLVEndomorphism_(self, curve, glvEndomorphism);
  return self;
}

- (LibOrgBouncycastleMathEcECPoint *)multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                                  withJavaMathBigInteger:(JavaMathBigInteger *)k {
  if (![((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve_)) equalsWithLibOrgBouncycastleMathEcECCurve:[((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) getCurve]]) {
    @throw new_JavaLangIllegalStateException_init();
  }
  JavaMathBigInteger *n = [((LibOrgBouncycastleMathEcECCurve *) nil_chk([p getCurve])) getOrder];
  IOSObjectArray *ab = [((id<LibOrgBouncycastleMathEcEndoGLVEndomorphism>) nil_chk(glvEndomorphism_)) decomposeScalarWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(k)) modWithJavaMathBigInteger:n]];
  JavaMathBigInteger *a = IOSObjectArray_Get(nil_chk(ab), 0);
  JavaMathBigInteger *b = IOSObjectArray_Get(ab, 1);
  id<LibOrgBouncycastleMathEcECPointMap> pointMap = [glvEndomorphism_ getPointMap];
  if ([glvEndomorphism_ hasEfficientPointMap]) {
    return LibOrgBouncycastleMathEcECAlgorithms_implShamirsTrickWNafWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECPointMap_withJavaMathBigInteger_(p, a, pointMap, b);
  }
  return LibOrgBouncycastleMathEcECAlgorithms_implShamirsTrickWNafWithLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_(p, a, [((id<LibOrgBouncycastleMathEcECPointMap>) nil_chk(pointMap)) mapWithLibOrgBouncycastleMathEcECPoint:p], b);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, 1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcECCurve:withLibOrgBouncycastleMathEcEndoGLVEndomorphism:);
  methods[1].selector = @selector(multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "curve_", "LLibOrgBouncycastleMathEcECCurve;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
    { "glvEndomorphism_", "LLibOrgBouncycastleMathEcEndoGLVEndomorphism;", .constantValue.asLong = 0, 0x14, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleMathEcECCurve;LLibOrgBouncycastleMathEcEndoGLVEndomorphism;", "multiplyPositive", "LLibOrgBouncycastleMathEcECPoint;LJavaMathBigInteger;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcGLVMultiplier = { "GLVMultiplier", "lib.org.bouncycastle.math.ec", ptrTable, methods, fields, 7, 0x1, 2, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcGLVMultiplier;
}

@end

void LibOrgBouncycastleMathEcGLVMultiplier_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcEndoGLVEndomorphism_(LibOrgBouncycastleMathEcGLVMultiplier *self, LibOrgBouncycastleMathEcECCurve *curve, id<LibOrgBouncycastleMathEcEndoGLVEndomorphism> glvEndomorphism) {
  LibOrgBouncycastleMathEcAbstractECMultiplier_init(self);
  if (curve == nil || [curve getOrder] == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Need curve with known group order");
  }
  self->curve_ = curve;
  self->glvEndomorphism_ = glvEndomorphism;
}

LibOrgBouncycastleMathEcGLVMultiplier *new_LibOrgBouncycastleMathEcGLVMultiplier_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcEndoGLVEndomorphism_(LibOrgBouncycastleMathEcECCurve *curve, id<LibOrgBouncycastleMathEcEndoGLVEndomorphism> glvEndomorphism) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcGLVMultiplier, initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcEndoGLVEndomorphism_, curve, glvEndomorphism)
}

LibOrgBouncycastleMathEcGLVMultiplier *create_LibOrgBouncycastleMathEcGLVMultiplier_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcEndoGLVEndomorphism_(LibOrgBouncycastleMathEcECCurve *curve, id<LibOrgBouncycastleMathEcEndoGLVEndomorphism> glvEndomorphism) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcGLVMultiplier, initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcEndoGLVEndomorphism_, curve, glvEndomorphism)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcGLVMultiplier)
