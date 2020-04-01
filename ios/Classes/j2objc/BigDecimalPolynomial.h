//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/ntru/polynomial/BigDecimalPolynomial.java
//

#ifndef BigDecimalPolynomial_H
#define BigDecimalPolynomial_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial;

@interface LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial : NSObject {
 @public
  IOSObjectArray *coeffs_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)p;

- (void)addWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)b;

- (id)java_clone;

- (IOSObjectArray *)getCoeffs;

- (void)halve;

- (LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)poly2;

- (LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)multWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)poly2;

- (LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *)round;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaMathBigDecimalArray:(IOSObjectArray *)coeffs;

- (instancetype __nonnull)initWithInt:(jint)N;

- (void)subWithLibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *)b;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial)

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial, coeffs_, IOSObjectArray *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, jint N);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(jint N) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *create_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithInt_(jint N);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, IOSObjectArray *coeffs);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(IOSObjectArray *coeffs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *create_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithJavaMathBigDecimalArray_(IOSObjectArray *coeffs);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *self, LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *p);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *new_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *p) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial *create_LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial_initWithLibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialBigIntPolynomial *p);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathNtruPolynomialBigDecimalPolynomial)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BigDecimalPolynomial_H