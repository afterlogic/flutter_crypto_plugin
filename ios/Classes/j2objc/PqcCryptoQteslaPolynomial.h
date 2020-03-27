//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/qtesla/PqcCryptoQteslaPolynomial.java
//

#ifndef PqcCryptoQteslaPolynomial_H
#define PqcCryptoQteslaPolynomial_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class IOSLongArray;
@class IOSShortArray;

@interface LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial : NSObject
@property (readonly, class) jint RANDOM NS_SWIFT_NAME(RANDOM);
@property (readonly, class) jint SEED NS_SWIFT_NAME(SEED);
@property (readonly, class) jint HASH NS_SWIFT_NAME(HASH);
@property (readonly, class) jint MESSAGE NS_SWIFT_NAME(MESSAGE);
@property (readonly, class) jint SIGNATURE_I NS_SWIFT_NAME(SIGNATURE_I);
@property (readonly, class) jint SIGNATURE_III_SIZE NS_SWIFT_NAME(SIGNATURE_III_SIZE);
@property (readonly, class) jint SIGNATURE_III_SPEED NS_SWIFT_NAME(SIGNATURE_III_SPEED);
@property (readonly, class) jint SIGNATURE_I_P NS_SWIFT_NAME(SIGNATURE_I_P);
@property (readonly, class) jint SIGNATURE_III_P NS_SWIFT_NAME(SIGNATURE_III_P);
@property (readonly, class) jint PUBLIC_KEY_I NS_SWIFT_NAME(PUBLIC_KEY_I);
@property (readonly, class) jint PUBLIC_KEY_III_SIZE NS_SWIFT_NAME(PUBLIC_KEY_III_SIZE);
@property (readonly, class) jint PUBLIC_KEY_III_SPEED NS_SWIFT_NAME(PUBLIC_KEY_III_SPEED);
@property (readonly, class) jint PUBLIC_KEY_I_P NS_SWIFT_NAME(PUBLIC_KEY_I_P);
@property (readonly, class) jint PUBLIC_KEY_III_P NS_SWIFT_NAME(PUBLIC_KEY_III_P);
@property (readonly, class) jint PRIVATE_KEY_I NS_SWIFT_NAME(PRIVATE_KEY_I);
@property (readonly, class) jint PRIVATE_KEY_III_SIZE NS_SWIFT_NAME(PRIVATE_KEY_III_SIZE);
@property (readonly, class) jint PRIVATE_KEY_III_SPEED NS_SWIFT_NAME(PRIVATE_KEY_III_SPEED);
@property (readonly, class) jint PRIVATE_KEY_I_P NS_SWIFT_NAME(PRIVATE_KEY_I_P);
@property (readonly, class) jint PRIVATE_KEY_III_P NS_SWIFT_NAME(PRIVATE_KEY_III_P);

+ (jint)RANDOM;

+ (jint)SEED;

+ (jint)HASH;

+ (jint)MESSAGE;

+ (jint)SIGNATURE_I;

+ (jint)SIGNATURE_III_SIZE;

+ (jint)SIGNATURE_III_SPEED;

+ (jint)SIGNATURE_I_P;

+ (jint)SIGNATURE_III_P;

+ (jint)PUBLIC_KEY_I;

+ (jint)PUBLIC_KEY_III_SIZE;

+ (jint)PUBLIC_KEY_III_SPEED;

+ (jint)PUBLIC_KEY_I_P;

+ (jint)PUBLIC_KEY_III_P;

+ (jint)PRIVATE_KEY_I;

+ (jint)PRIVATE_KEY_III_SIZE;

+ (jint)PRIVATE_KEY_III_SPEED;

+ (jint)PRIVATE_KEY_I_P;

+ (jint)PRIVATE_KEY_III_P;

#pragma mark Public

+ (jint)barrettWithInt:(jint)number
               withInt:(jint)q
               withInt:(jint)barrettMultiplication
               withInt:(jint)barrettDivision;

+ (jlong)barrettWithLong:(jlong)number
                 withInt:(jint)q
                 withInt:(jint)barrettMultiplication
                 withInt:(jint)barrettDivision;

+ (void)polynomialAdditionWithIntArray:(IOSIntArray *)summation
                          withIntArray:(IOSIntArray *)augend
                          withIntArray:(IOSIntArray *)addend
                               withInt:(jint)n;

+ (void)polynomialAdditionWithLongArray:(IOSLongArray *)summation
                                withInt:(jint)summationOffset
                          withLongArray:(IOSLongArray *)augend
                                withInt:(jint)augendOffset
                          withLongArray:(IOSLongArray *)addend
                                withInt:(jint)addendOffset
                                withInt:(jint)n;

+ (void)polynomialAdditionCorrectionWithIntArray:(IOSIntArray *)summation
                                    withIntArray:(IOSIntArray *)augend
                                    withIntArray:(IOSIntArray *)addend
                                         withInt:(jint)n
                                         withInt:(jint)q;

+ (void)polynomialMultiplicationWithIntArray:(IOSIntArray *)product
                                withIntArray:(IOSIntArray *)multiplicand
                                withIntArray:(IOSIntArray *)multiplier
                                     withInt:(jint)n
                                     withInt:(jint)q
                                    withLong:(jlong)qInverse
                                withIntArray:(IOSIntArray *)zeta;

+ (void)polynomialMultiplicationWithLongArray:(IOSLongArray *)product
                                      withInt:(jint)productOffset
                                withLongArray:(IOSLongArray *)multiplicand
                                      withInt:(jint)multiplicandOffset
                                withLongArray:(IOSLongArray *)multiplier
                                      withInt:(jint)multiplierOffset
                                      withInt:(jint)n
                                      withInt:(jint)q
                                     withLong:(jlong)qInverse;

+ (void)polynomialNumberTheoreticTransformWithLongArray:(IOSLongArray *)arrayNumberTheoreticTransform
                                          withLongArray:(IOSLongArray *)array
                                                withInt:(jint)n;

+ (void)polynomialSubtractionWithLongArray:(IOSLongArray *)difference
                                   withInt:(jint)differenceOffset
                             withLongArray:(IOSLongArray *)minuend
                                   withInt:(jint)minuendOffset
                             withLongArray:(IOSLongArray *)subtrahend
                                   withInt:(jint)subtrahendOffset
                                   withInt:(jint)n
                                   withInt:(jint)q
                                   withInt:(jint)barrettMultiplication
                                   withInt:(jint)barrettDivision;

+ (void)polynomialSubtractionCorrectionWithIntArray:(IOSIntArray *)difference
                                       withIntArray:(IOSIntArray *)minuend
                                       withIntArray:(IOSIntArray *)subtrahend
                                            withInt:(jint)n
                                            withInt:(jint)q;

+ (void)polynomialSubtractionMontgomeryWithIntArray:(IOSIntArray *)difference
                                       withIntArray:(IOSIntArray *)minuend
                                       withIntArray:(IOSIntArray *)subtrahend
                                            withInt:(jint)n
                                            withInt:(jint)q
                                           withLong:(jlong)qInverse
                                            withInt:(jint)r;

+ (void)polynomialUniformWithIntArray:(IOSIntArray *)A
                        withByteArray:(IOSByteArray *)seed
                              withInt:(jint)seedOffset
                              withInt:(jint)n
                              withInt:(jint)q
                             withLong:(jlong)qInverse
                              withInt:(jint)qLogarithm
                              withInt:(jint)generatorA
                              withInt:(jint)inverseNumberTheoreticTransform;

+ (void)polynomialUniformWithLongArray:(IOSLongArray *)A
                         withByteArray:(IOSByteArray *)seed
                               withInt:(jint)seedOffset
                               withInt:(jint)n
                               withInt:(jint)k
                               withInt:(jint)q
                              withLong:(jlong)qInverse
                               withInt:(jint)qLogarithm
                               withInt:(jint)generatorA
                               withInt:(jint)inverseNumberTheoreticTransform;

+ (void)sparsePolynomialMultiplication16WithIntArray:(IOSIntArray *)product
                                      withShortArray:(IOSShortArray *)privateKey
                                        withIntArray:(IOSIntArray *)positionList
                                      withShortArray:(IOSShortArray *)signList
                                             withInt:(jint)n
                                             withInt:(jint)h;

+ (void)sparsePolynomialMultiplication32WithIntArray:(IOSIntArray *)product
                                        withIntArray:(IOSIntArray *)publicKey
                                        withIntArray:(IOSIntArray *)positionList
                                      withShortArray:(IOSShortArray *)signList
                                             withInt:(jint)n
                                             withInt:(jint)h;

+ (void)sparsePolynomialMultiplication32WithLongArray:(IOSLongArray *)product
                                              withInt:(jint)productOffset
                                         withIntArray:(IOSIntArray *)publicKey
                                              withInt:(jint)publicKeyOffset
                                         withIntArray:(IOSIntArray *)positionList
                                       withShortArray:(IOSShortArray *)signList
                                              withInt:(jint)n
                                              withInt:(jint)h
                                              withInt:(jint)q
                                              withInt:(jint)barrettMultiplication
                                              withInt:(jint)barrettDivision;

+ (void)sparsePolynomialMultiplication8WithLongArray:(IOSLongArray *)product
                                             withInt:(jint)productOffset
                                       withByteArray:(IOSByteArray *)privateKey
                                             withInt:(jint)privateKeyOffset
                                        withIntArray:(IOSIntArray *)positionList
                                      withShortArray:(IOSShortArray *)signList
                                             withInt:(jint)n
                                             withInt:(jint)h;

#pragma mark Package-Private

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_RANDOM(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_RANDOM 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, RANDOM, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_SEED(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_SEED 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, SEED, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_HASH(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_HASH 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, HASH, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_MESSAGE(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_MESSAGE 64
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, MESSAGE, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_SIGNATURE_I(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_SIGNATURE_I 1376
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, SIGNATURE_I, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_SIGNATURE_III_SIZE(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_SIGNATURE_III_SIZE 2720
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, SIGNATURE_III_SIZE, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_SIGNATURE_III_SPEED(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_SIGNATURE_III_SPEED 2848
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, SIGNATURE_III_SPEED, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_SIGNATURE_I_P(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_SIGNATURE_I_P 2848
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, SIGNATURE_I_P, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_SIGNATURE_III_P(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_SIGNATURE_III_P 6176
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, SIGNATURE_III_P, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_PUBLIC_KEY_I(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_PUBLIC_KEY_I 1504
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, PUBLIC_KEY_I, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_PUBLIC_KEY_III_SIZE(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_PUBLIC_KEY_III_SIZE 2976
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, PUBLIC_KEY_III_SIZE, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_PUBLIC_KEY_III_SPEED(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_PUBLIC_KEY_III_SPEED 3104
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, PUBLIC_KEY_III_SPEED, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_PUBLIC_KEY_I_P(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_PUBLIC_KEY_I_P 14880
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, PUBLIC_KEY_I_P, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_PUBLIC_KEY_III_P(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_PUBLIC_KEY_III_P 39712
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, PUBLIC_KEY_III_P, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_PRIVATE_KEY_I(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_PRIVATE_KEY_I 1344
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, PRIVATE_KEY_I, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_PRIVATE_KEY_III_SIZE(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_PRIVATE_KEY_III_SIZE 2112
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, PRIVATE_KEY_III_SIZE, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_PRIVATE_KEY_III_SPEED(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_PRIVATE_KEY_III_SPEED 2368
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, PRIVATE_KEY_III_SPEED, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_PRIVATE_KEY_I_P(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_PRIVATE_KEY_I_P 5184
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, PRIVATE_KEY_I_P, jint)

inline jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_get_PRIVATE_KEY_III_P(void);
#define LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_PRIVATE_KEY_III_P 12352
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial, PRIVATE_KEY_III_P, jint)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_init(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial *new_LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial *create_LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_init(void);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_barrettWithInt_withInt_withInt_withInt_(jint number, jint q, jint barrettMultiplication, jint barrettDivision);

FOUNDATION_EXPORT jlong LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_barrettWithLong_withInt_withInt_withInt_(jlong number, jint q, jint barrettMultiplication, jint barrettDivision);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialNumberTheoreticTransformWithLongArray_withLongArray_withInt_(IOSLongArray *arrayNumberTheoreticTransform, IOSLongArray *array, jint n);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialMultiplicationWithIntArray_withIntArray_withIntArray_withInt_withInt_withLong_withIntArray_(IOSIntArray *product, IOSIntArray *multiplicand, IOSIntArray *multiplier, jint n, jint q, jlong qInverse, IOSIntArray *zeta);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialMultiplicationWithLongArray_withInt_withLongArray_withInt_withLongArray_withInt_withInt_withInt_withLong_(IOSLongArray *product, jint productOffset, IOSLongArray *multiplicand, jint multiplicandOffset, IOSLongArray *multiplier, jint multiplierOffset, jint n, jint q, jlong qInverse);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialAdditionWithIntArray_withIntArray_withIntArray_withInt_(IOSIntArray *summation, IOSIntArray *augend, IOSIntArray *addend, jint n);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialAdditionWithLongArray_withInt_withLongArray_withInt_withLongArray_withInt_withInt_(IOSLongArray *summation, jint summationOffset, IOSLongArray *augend, jint augendOffset, IOSLongArray *addend, jint addendOffset, jint n);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialAdditionCorrectionWithIntArray_withIntArray_withIntArray_withInt_withInt_(IOSIntArray *summation, IOSIntArray *augend, IOSIntArray *addend, jint n, jint q);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialSubtractionCorrectionWithIntArray_withIntArray_withIntArray_withInt_withInt_(IOSIntArray *difference, IOSIntArray *minuend, IOSIntArray *subtrahend, jint n, jint q);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialSubtractionMontgomeryWithIntArray_withIntArray_withIntArray_withInt_withInt_withLong_withInt_(IOSIntArray *difference, IOSIntArray *minuend, IOSIntArray *subtrahend, jint n, jint q, jlong qInverse, jint r);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialSubtractionWithLongArray_withInt_withLongArray_withInt_withLongArray_withInt_withInt_withInt_withInt_withInt_(IOSLongArray *difference, jint differenceOffset, IOSLongArray *minuend, jint minuendOffset, IOSLongArray *subtrahend, jint subtrahendOffset, jint n, jint q, jint barrettMultiplication, jint barrettDivision);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialUniformWithIntArray_withByteArray_withInt_withInt_withInt_withLong_withInt_withInt_withInt_(IOSIntArray *A, IOSByteArray *seed, jint seedOffset, jint n, jint q, jlong qInverse, jint qLogarithm, jint generatorA, jint inverseNumberTheoreticTransform);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_polynomialUniformWithLongArray_withByteArray_withInt_withInt_withInt_withInt_withLong_withInt_withInt_withInt_(IOSLongArray *A, IOSByteArray *seed, jint seedOffset, jint n, jint k, jint q, jlong qInverse, jint qLogarithm, jint generatorA, jint inverseNumberTheoreticTransform);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_sparsePolynomialMultiplication16WithIntArray_withShortArray_withIntArray_withShortArray_withInt_withInt_(IOSIntArray *product, IOSShortArray *privateKey, IOSIntArray *positionList, IOSShortArray *signList, jint n, jint h);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_sparsePolynomialMultiplication8WithLongArray_withInt_withByteArray_withInt_withIntArray_withShortArray_withInt_withInt_(IOSLongArray *product, jint productOffset, IOSByteArray *privateKey, jint privateKeyOffset, IOSIntArray *positionList, IOSShortArray *signList, jint n, jint h);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_sparsePolynomialMultiplication32WithIntArray_withIntArray_withIntArray_withShortArray_withInt_withInt_(IOSIntArray *product, IOSIntArray *publicKey, IOSIntArray *positionList, IOSShortArray *signList, jint n, jint h);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial_sparsePolynomialMultiplication32WithLongArray_withInt_withIntArray_withInt_withIntArray_withShortArray_withInt_withInt_withInt_withInt_withInt_(IOSLongArray *product, jint productOffset, IOSIntArray *publicKey, jint publicKeyOffset, IOSIntArray *positionList, IOSShortArray *signList, jint n, jint h, jint q, jint barrettMultiplication, jint barrettDivision);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoQteslaPqcCryptoQteslaPolynomial)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PqcCryptoQteslaPolynomial_H
