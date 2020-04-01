//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/MixedNafR2LMultiplier.java
//

#ifndef MixedNafR2LMultiplier_H
#define MixedNafR2LMultiplier_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AbstractECMultiplier.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcECCurve;
@class LibOrgBouncycastleMathEcECPoint;

@interface LibOrgBouncycastleMathEcMixedNafR2LMultiplier : LibOrgBouncycastleMathEcAbstractECMultiplier {
 @public
  jint additionCoord_;
  jint doublingCoord_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithInt:(jint)additionCoord
                              withInt:(jint)doublingCoord;

#pragma mark Protected

- (LibOrgBouncycastleMathEcECCurve *)configureCurveWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)c
                                                                               withInt:(jint)coord;

- (LibOrgBouncycastleMathEcECPoint *)multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                                  withJavaMathBigInteger:(JavaMathBigInteger *)k;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcMixedNafR2LMultiplier)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcMixedNafR2LMultiplier_init(LibOrgBouncycastleMathEcMixedNafR2LMultiplier *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcMixedNafR2LMultiplier *new_LibOrgBouncycastleMathEcMixedNafR2LMultiplier_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcMixedNafR2LMultiplier *create_LibOrgBouncycastleMathEcMixedNafR2LMultiplier_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcMixedNafR2LMultiplier_initWithInt_withInt_(LibOrgBouncycastleMathEcMixedNafR2LMultiplier *self, jint additionCoord, jint doublingCoord);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcMixedNafR2LMultiplier *new_LibOrgBouncycastleMathEcMixedNafR2LMultiplier_initWithInt_withInt_(jint additionCoord, jint doublingCoord) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcMixedNafR2LMultiplier *create_LibOrgBouncycastleMathEcMixedNafR2LMultiplier_initWithInt_withInt_(jint additionCoord, jint doublingCoord);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcMixedNafR2LMultiplier)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // MixedNafR2LMultiplier_H