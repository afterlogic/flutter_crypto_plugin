//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/rfc7748/X448.java
//

#ifndef X448_H
#define X448_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;

@interface LibOrgBouncycastleMathEcRfc7748X448 : NSObject
@property (readonly, class) jint POINT_SIZE NS_SWIFT_NAME(POINT_SIZE);
@property (readonly, class) jint SCALAR_SIZE NS_SWIFT_NAME(SCALAR_SIZE);

+ (jint)POINT_SIZE;

+ (jint)SCALAR_SIZE;

#pragma mark Public

- (instancetype __nonnull)init;

+ (jboolean)calculateAgreementWithByteArray:(IOSByteArray *)k
                                    withInt:(jint)kOff
                              withByteArray:(IOSByteArray *)u
                                    withInt:(jint)uOff
                              withByteArray:(IOSByteArray *)r
                                    withInt:(jint)rOff;

+ (void)generatePrivateKeyWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random
                                         withByteArray:(IOSByteArray *)k;

+ (void)generatePublicKeyWithByteArray:(IOSByteArray *)k
                               withInt:(jint)kOff
                         withByteArray:(IOSByteArray *)r
                               withInt:(jint)rOff;

+ (void)precompute;

+ (void)scalarMultWithByteArray:(IOSByteArray *)k
                        withInt:(jint)kOff
                  withByteArray:(IOSByteArray *)u
                        withInt:(jint)uOff
                  withByteArray:(IOSByteArray *)r
                        withInt:(jint)rOff;

+ (void)scalarMultBaseWithByteArray:(IOSByteArray *)k
                            withInt:(jint)kOff
                      withByteArray:(IOSByteArray *)r
                            withInt:(jint)rOff;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcRfc7748X448)

inline jint LibOrgBouncycastleMathEcRfc7748X448_get_POINT_SIZE(void);
#define LibOrgBouncycastleMathEcRfc7748X448_POINT_SIZE 56
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcRfc7748X448, POINT_SIZE, jint)

inline jint LibOrgBouncycastleMathEcRfc7748X448_get_SCALAR_SIZE(void);
#define LibOrgBouncycastleMathEcRfc7748X448_SCALAR_SIZE 56
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcRfc7748X448, SCALAR_SIZE, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcRfc7748X448_init(LibOrgBouncycastleMathEcRfc7748X448 *self);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleMathEcRfc7748X448_calculateAgreementWithByteArray_withInt_withByteArray_withInt_withByteArray_withInt_(IOSByteArray *k, jint kOff, IOSByteArray *u, jint uOff, IOSByteArray *r, jint rOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcRfc7748X448_generatePrivateKeyWithJavaSecuritySecureRandom_withByteArray_(JavaSecuritySecureRandom *random, IOSByteArray *k);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcRfc7748X448_generatePublicKeyWithByteArray_withInt_withByteArray_withInt_(IOSByteArray *k, jint kOff, IOSByteArray *r, jint rOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcRfc7748X448_precompute(void);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcRfc7748X448_scalarMultWithByteArray_withInt_withByteArray_withInt_withByteArray_withInt_(IOSByteArray *k, jint kOff, IOSByteArray *u, jint uOff, IOSByteArray *r, jint rOff);

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcRfc7748X448_scalarMultBaseWithByteArray_withInt_withByteArray_withInt_(IOSByteArray *k, jint kOff, IOSByteArray *r, jint rOff);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcRfc7748X448)

@interface LibOrgBouncycastleMathEcRfc7748X448_Friend : NSObject

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleMathEcRfc7748X448_Friend)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcRfc7748X448_Friend)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X448_H
