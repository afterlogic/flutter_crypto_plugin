//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/math/ntru/polynomial/LongPolynomial2.java
//

#ifndef LongPolynomial2_H
#define LongPolynomial2_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;

@interface LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2 : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)p;

- (id)java_clone;

- (jboolean)isEqual:(id)obj;

- (LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2 *)multWithLibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2:(LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2 *)poly2;

- (void)mult2AndWithInt:(jint)mask;

- (void)subAndWithLibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2:(LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2 *)b
                                                                 withInt:(jint)mask;

- (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)toIntegerPolynomial;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2 *self, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *p);

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2 *new_LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *p) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2 *create_LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *p);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcMathNtruPolynomialLongPolynomial2)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // LongPolynomial2_H
