//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/linearalgebra/Permutation.java
//

#ifndef Permutation_H
#define Permutation_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;
@class JavaSecuritySecureRandom;

@interface LibOrgBouncycastlePqcMathLinearalgebraPermutation : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)enc;

- (instancetype __nonnull)initWithInt:(jint)n;

- (instancetype __nonnull)initWithInt:(jint)n
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)sr;

- (instancetype __nonnull)initWithIntArray:(IOSIntArray *)perm;

- (LibOrgBouncycastlePqcMathLinearalgebraPermutation *)computeInverse;

- (jboolean)isEqual:(id)other;

- (IOSByteArray *)getEncoded;

- (IOSIntArray *)getVector;

- (NSUInteger)hash;

- (LibOrgBouncycastlePqcMathLinearalgebraPermutation *)rightMultiplyWithLibOrgBouncycastlePqcMathLinearalgebraPermutation:(LibOrgBouncycastlePqcMathLinearalgebraPermutation *)p;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcMathLinearalgebraPermutation)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_(LibOrgBouncycastlePqcMathLinearalgebraPermutation *self, jint n);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraPermutation *new_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_(jint n) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraPermutation *create_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_(jint n);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithIntArray_(LibOrgBouncycastlePqcMathLinearalgebraPermutation *self, IOSIntArray *perm);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraPermutation *new_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithIntArray_(IOSIntArray *perm) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraPermutation *create_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithIntArray_(IOSIntArray *perm);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithByteArray_(LibOrgBouncycastlePqcMathLinearalgebraPermutation *self, IOSByteArray *enc);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraPermutation *new_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithByteArray_(IOSByteArray *enc) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraPermutation *create_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithByteArray_(IOSByteArray *enc);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_withJavaSecuritySecureRandom_(LibOrgBouncycastlePqcMathLinearalgebraPermutation *self, jint n, JavaSecuritySecureRandom *sr);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraPermutation *new_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_withJavaSecuritySecureRandom_(jint n, JavaSecuritySecureRandom *sr) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathLinearalgebraPermutation *create_LibOrgBouncycastlePqcMathLinearalgebraPermutation_initWithInt_withJavaSecuritySecureRandom_(jint n, JavaSecuritySecureRandom *sr);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathLinearalgebraPermutation)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Permutation_H
