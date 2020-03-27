//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/sec/SecT193R2Curve.java
//

#ifndef SecT193R2Curve_H
#define SecT193R2Curve_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECCurve.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcCustomSecSecT193R2Point;
@class LibOrgBouncycastleMathEcECFieldElement;
@class LibOrgBouncycastleMathEcECPoint;
@protocol LibOrgBouncycastleMathEcECLookupTable;

@interface LibOrgBouncycastleMathEcCustomSecSecT193R2Curve : LibOrgBouncycastleMathEcECCurve_AbstractF2m {
 @public
  LibOrgBouncycastleMathEcCustomSecSecT193R2Point *infinity_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (id<LibOrgBouncycastleMathEcECLookupTable>)createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                                                                        withInt:(jint)off
                                                                                                        withInt:(jint)len;

- (LibOrgBouncycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (jint)getFieldSize;

- (LibOrgBouncycastleMathEcECPoint *)getInfinity;

- (jint)getK1;

- (jint)getK2;

- (jint)getK3;

- (jint)getM;

- (jboolean)isKoblitz;

- (jboolean)isTrinomial;

- (jboolean)supportsCoordinateSystemWithInt:(jint)coord;

#pragma mark Protected

- (LibOrgBouncycastleMathEcECCurve *)cloneCurve;

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                                                                  withBoolean:(jboolean)withCompression;

- (LibOrgBouncycastleMathEcECPoint *)createRawPointWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)x
                                                   withLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)y
                                              withLibOrgBouncycastleMathEcECFieldElementArray:(IOSObjectArray *)zs
                                                                                  withBoolean:(jboolean)withCompression;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0
                              withInt:(jint)arg1
                              withInt:(jint)arg2
                              withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcCustomSecSecT193R2Curve)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcCustomSecSecT193R2Curve, infinity_, LibOrgBouncycastleMathEcCustomSecSecT193R2Point *)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomSecSecT193R2Curve_init(LibOrgBouncycastleMathEcCustomSecSecT193R2Curve *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT193R2Curve *new_LibOrgBouncycastleMathEcCustomSecSecT193R2Curve_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomSecSecT193R2Curve *create_LibOrgBouncycastleMathEcCustomSecSecT193R2Curve_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcCustomSecSecT193R2Curve)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SecT193R2Curve_H
