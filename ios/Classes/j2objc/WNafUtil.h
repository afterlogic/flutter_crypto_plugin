//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/WNafUtil.java
//

#ifndef WNafUtil_H
#define WNafUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleMathEcECPoint;
@class LibOrgBouncycastleMathEcWNafPreCompInfo;
@protocol LibOrgBouncycastleMathEcECPointMap;
@protocol LibOrgBouncycastleMathEcPreCompInfo;

@interface LibOrgBouncycastleMathEcWNafUtil : NSObject
@property (readonly, copy, class) NSString *PRECOMP_NAME NS_SWIFT_NAME(PRECOMP_NAME);

+ (NSString *)PRECOMP_NAME;

#pragma mark Public

- (instancetype __nonnull)init;

+ (IOSIntArray *)generateCompactNafWithJavaMathBigInteger:(JavaMathBigInteger *)k;

+ (IOSIntArray *)generateCompactWindowNafWithInt:(jint)width
                          withJavaMathBigInteger:(JavaMathBigInteger *)k;

+ (IOSByteArray *)generateJSFWithJavaMathBigInteger:(JavaMathBigInteger *)g
                             withJavaMathBigInteger:(JavaMathBigInteger *)h;

+ (IOSByteArray *)generateNafWithJavaMathBigInteger:(JavaMathBigInteger *)k;

+ (IOSByteArray *)generateWindowNafWithInt:(jint)width
                    withJavaMathBigInteger:(JavaMathBigInteger *)k;

+ (jint)getNafWeightWithJavaMathBigInteger:(JavaMathBigInteger *)k;

+ (jint)getWindowSizeWithInt:(jint)bits;

+ (jint)getWindowSizeWithInt:(jint)bits
                withIntArray:(IOSIntArray *)windowSizeCutoffs;

+ (LibOrgBouncycastleMathEcWNafPreCompInfo *)getWNafPreCompInfoWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p;

+ (LibOrgBouncycastleMathEcWNafPreCompInfo *)getWNafPreCompInfoWithLibOrgBouncycastleMathEcPreCompInfo:(id<LibOrgBouncycastleMathEcPreCompInfo>)preCompInfo;

+ (LibOrgBouncycastleMathEcECPoint *)mapPointWithPrecompWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                                                    withInt:(jint)width
                                                                                withBoolean:(jboolean)includeNegated
                                                     withLibOrgBouncycastleMathEcECPointMap:(id<LibOrgBouncycastleMathEcECPointMap>)pointMap;

+ (LibOrgBouncycastleMathEcWNafPreCompInfo *)precomputeWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p
                                                                                   withInt:(jint)width
                                                                               withBoolean:(jboolean)includeNegated;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleMathEcWNafUtil)

inline NSString *LibOrgBouncycastleMathEcWNafUtil_get_PRECOMP_NAME(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastleMathEcWNafUtil_PRECOMP_NAME;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleMathEcWNafUtil, PRECOMP_NAME, NSString *)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcWNafUtil_init(LibOrgBouncycastleMathEcWNafUtil *self);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathEcWNafUtil_generateCompactNafWithJavaMathBigInteger_(JavaMathBigInteger *k);

FOUNDATION_EXPORT IOSIntArray *LibOrgBouncycastleMathEcWNafUtil_generateCompactWindowNafWithInt_withJavaMathBigInteger_(jint width, JavaMathBigInteger *k);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleMathEcWNafUtil_generateJSFWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *g, JavaMathBigInteger *h);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleMathEcWNafUtil_generateNafWithJavaMathBigInteger_(JavaMathBigInteger *k);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleMathEcWNafUtil_generateWindowNafWithInt_withJavaMathBigInteger_(jint width, JavaMathBigInteger *k);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathEcWNafUtil_getNafWeightWithJavaMathBigInteger_(JavaMathBigInteger *k);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcWNafPreCompInfo *LibOrgBouncycastleMathEcWNafUtil_getWNafPreCompInfoWithLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleMathEcECPoint *p);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcWNafPreCompInfo *LibOrgBouncycastleMathEcWNafUtil_getWNafPreCompInfoWithLibOrgBouncycastleMathEcPreCompInfo_(id<LibOrgBouncycastleMathEcPreCompInfo> preCompInfo);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathEcWNafUtil_getWindowSizeWithInt_(jint bits);

FOUNDATION_EXPORT jint LibOrgBouncycastleMathEcWNafUtil_getWindowSizeWithInt_withIntArray_(jint bits, IOSIntArray *windowSizeCutoffs);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcECPoint *LibOrgBouncycastleMathEcWNafUtil_mapPointWithPrecompWithLibOrgBouncycastleMathEcECPoint_withInt_withBoolean_withLibOrgBouncycastleMathEcECPointMap_(LibOrgBouncycastleMathEcECPoint *p, jint width, jboolean includeNegated, id<LibOrgBouncycastleMathEcECPointMap> pointMap);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcWNafPreCompInfo *LibOrgBouncycastleMathEcWNafUtil_precomputeWithLibOrgBouncycastleMathEcECPoint_withInt_withBoolean_(LibOrgBouncycastleMathEcECPoint *p, jint width, jboolean includeNegated);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcWNafUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // WNafUtil_H
