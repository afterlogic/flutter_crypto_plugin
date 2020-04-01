//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/qtesla/Sample.java
//

#ifndef Sample_H
#define Sample_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSLongArray;
@class IOSObjectArray;
@class IOSShortArray;

@interface LibOrgBouncycastlePqcCryptoQteslaSample : NSObject
@property (readonly, class) IOSObjectArray *EXPONENTIAL_DISTRIBUTION_I NS_SWIFT_NAME(EXPONENTIAL_DISTRIBUTION_I);
@property (readonly, class) IOSObjectArray *EXPONENTIAL_DISTRIBUTION_III_SIZE NS_SWIFT_NAME(EXPONENTIAL_DISTRIBUTION_III_SIZE);
@property (readonly, class) IOSObjectArray *EXPONENTIAL_DISTRIBUTION_III_SPEED NS_SWIFT_NAME(EXPONENTIAL_DISTRIBUTION_III_SPEED);
@property (readonly, class) IOSObjectArray *EXPONENTIAL_DISTRIBUTION_P NS_SWIFT_NAME(EXPONENTIAL_DISTRIBUTION_P);
@property (readonly, class) IOSObjectArray *CUMULATIVE_DISTRIBUTION_TABLE_I NS_SWIFT_NAME(CUMULATIVE_DISTRIBUTION_TABLE_I);
@property (readonly, class) IOSObjectArray *CUMULATIVE_DISTRIBUTION_TABLE_III NS_SWIFT_NAME(CUMULATIVE_DISTRIBUTION_TABLE_III);

+ (IOSObjectArray *)EXPONENTIAL_DISTRIBUTION_I;

+ (IOSObjectArray *)EXPONENTIAL_DISTRIBUTION_III_SIZE;

+ (IOSObjectArray *)EXPONENTIAL_DISTRIBUTION_III_SPEED;

+ (IOSObjectArray *)EXPONENTIAL_DISTRIBUTION_P;

+ (IOSObjectArray *)CUMULATIVE_DISTRIBUTION_TABLE_I;

+ (IOSObjectArray *)CUMULATIVE_DISTRIBUTION_TABLE_III;

#pragma mark Public

+ (void)encodeCWithIntArray:(IOSIntArray *)positionList
             withShortArray:(IOSShortArray *)signList
              withByteArray:(IOSByteArray *)output
                    withInt:(jint)outputOffset
                    withInt:(jint)n
                    withInt:(jint)h;

+ (void)polynomialGaussSamplerIWithIntArray:(IOSIntArray *)data
                                    withInt:(jint)dataOffset
                              withByteArray:(IOSByteArray *)seed
                                    withInt:(jint)seedOffset
                                    withInt:(jint)nonce;

+ (void)polynomialGaussSamplerIIIWithIntArray:(IOSIntArray *)data
                                      withInt:(jint)dataOffset
                                withByteArray:(IOSByteArray *)seed
                                      withInt:(jint)seedOffset
                                      withInt:(jint)nonce
                                      withInt:(jint)n
                                   withDouble:(jdouble)xi
                             withDoubleArray2:(IOSObjectArray *)exponentialDistribution;

+ (void)polynomialGaussSamplerIIIPWithLongArray:(IOSLongArray *)data
                                        withInt:(jint)dataOffset
                                  withByteArray:(IOSByteArray *)seed
                                        withInt:(jint)seedOffset
                                        withInt:(jint)nonce;

+ (void)polynomialGaussSamplerIPWithLongArray:(IOSLongArray *)data
                                      withInt:(jint)dataOffset
                                withByteArray:(IOSByteArray *)seed
                                      withInt:(jint)seedOffset
                                      withInt:(jint)nonce;

+ (void)sampleYWithIntArray:(IOSIntArray *)Y
              withByteArray:(IOSByteArray *)seed
                    withInt:(jint)seedOffset
                    withInt:(jint)nonce
                    withInt:(jint)n
                    withInt:(jint)q
                    withInt:(jint)b
                    withInt:(jint)bBit;

+ (void)sampleYWithLongArray:(IOSLongArray *)Y
               withByteArray:(IOSByteArray *)seed
                     withInt:(jint)seedOffset
                     withInt:(jint)nonce
                     withInt:(jint)n
                     withInt:(jint)q
                     withInt:(jint)b
                     withInt:(jint)bBit;

#pragma mark Package-Private

- (instancetype __nonnull)init;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastlePqcCryptoQteslaSample)

inline IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_get_EXPONENTIAL_DISTRIBUTION_I(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_EXPONENTIAL_DISTRIBUTION_I;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoQteslaSample, EXPONENTIAL_DISTRIBUTION_I, IOSObjectArray *)

inline IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_get_EXPONENTIAL_DISTRIBUTION_III_SIZE(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_EXPONENTIAL_DISTRIBUTION_III_SIZE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoQteslaSample, EXPONENTIAL_DISTRIBUTION_III_SIZE, IOSObjectArray *)

inline IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_get_EXPONENTIAL_DISTRIBUTION_III_SPEED(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_EXPONENTIAL_DISTRIBUTION_III_SPEED;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoQteslaSample, EXPONENTIAL_DISTRIBUTION_III_SPEED, IOSObjectArray *)

inline IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_get_EXPONENTIAL_DISTRIBUTION_P(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_EXPONENTIAL_DISTRIBUTION_P;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoQteslaSample, EXPONENTIAL_DISTRIBUTION_P, IOSObjectArray *)

inline IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_get_CUMULATIVE_DISTRIBUTION_TABLE_I(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_CUMULATIVE_DISTRIBUTION_TABLE_I;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoQteslaSample, CUMULATIVE_DISTRIBUTION_TABLE_I, IOSObjectArray *)

inline IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_get_CUMULATIVE_DISTRIBUTION_TABLE_III(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastlePqcCryptoQteslaSample_CUMULATIVE_DISTRIBUTION_TABLE_III;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcCryptoQteslaSample, CUMULATIVE_DISTRIBUTION_TABLE_III, IOSObjectArray *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaSample_init(LibOrgBouncycastlePqcCryptoQteslaSample *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaSample *new_LibOrgBouncycastlePqcCryptoQteslaSample_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaSample *create_LibOrgBouncycastlePqcCryptoQteslaSample_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaSample_sampleYWithIntArray_withByteArray_withInt_withInt_withInt_withInt_withInt_withInt_(IOSIntArray *Y, IOSByteArray *seed, jint seedOffset, jint nonce, jint n, jint q, jint b, jint bBit);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaSample_sampleYWithLongArray_withByteArray_withInt_withInt_withInt_withInt_withInt_withInt_(IOSLongArray *Y, IOSByteArray *seed, jint seedOffset, jint nonce, jint n, jint q, jint b, jint bBit);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaSample_polynomialGaussSamplerIWithIntArray_withInt_withByteArray_withInt_withInt_(IOSIntArray *data, jint dataOffset, IOSByteArray *seed, jint seedOffset, jint nonce);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaSample_polynomialGaussSamplerIPWithLongArray_withInt_withByteArray_withInt_withInt_(IOSLongArray *data, jint dataOffset, IOSByteArray *seed, jint seedOffset, jint nonce);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaSample_polynomialGaussSamplerIIIWithIntArray_withInt_withByteArray_withInt_withInt_withInt_withDouble_withDoubleArray2_(IOSIntArray *data, jint dataOffset, IOSByteArray *seed, jint seedOffset, jint nonce, jint n, jdouble xi, IOSObjectArray *exponentialDistribution);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaSample_polynomialGaussSamplerIIIPWithLongArray_withInt_withByteArray_withInt_withInt_(IOSLongArray *data, jint dataOffset, IOSByteArray *seed, jint seedOffset, jint nonce);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaSample_encodeCWithIntArray_withShortArray_withByteArray_withInt_withInt_withInt_(IOSIntArray *positionList, IOSShortArray *signList, IOSByteArray *output, jint outputOffset, jint n, jint h);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoQteslaSample)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Sample_H