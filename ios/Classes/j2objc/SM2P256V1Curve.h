//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/custom/gm/SM2P256V1Curve.java
//

#ifndef SM2P256V1Curve_H
#define SM2P256V1Curve_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECCurve.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcCustomGmSM2P256V1Point;
@class LibOrgBouncycastleMathEcECFieldElement;
@class LibOrgBouncycastleMathEcECPoint;
@protocol LibOrgBouncycastleMathEcECLookupTable;

@interface LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve : LibOrgBouncycastleMathEcECCurve_AbstractFp {
 @public
  LibOrgBouncycastleMathEcCustomGmSM2P256V1Point *infinity_;
}
@property (readonly, class) JavaMathBigInteger *q NS_SWIFT_NAME(q);

+ (JavaMathBigInteger *)q;

#pragma mark Public

- (instancetype __nonnull)init;

- (id<LibOrgBouncycastleMathEcECLookupTable>)createCacheSafeLookupTableWithLibOrgBouncycastleMathEcECPointArray:(IOSObjectArray *)points
                                                                                                        withInt:(jint)off
                                                                                                        withInt:(jint)len;

- (LibOrgBouncycastleMathEcECFieldElement *)fromBigIntegerWithJavaMathBigInteger:(JavaMathBigInteger *)x;

- (jint)getFieldSize;

- (LibOrgBouncycastleMathEcECPoint *)getInfinity;

- (JavaMathBigInteger *)getQ;

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

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve, infinity_, LibOrgBouncycastleMathEcCustomGmSM2P256V1Point *)

inline JavaMathBigInteger *LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve_get_q(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve_q;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve, q, JavaMathBigInteger *)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve_init(LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve *new_LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve *create_LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcCustomGmSM2P256V1Curve)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SM2P256V1Curve_H
