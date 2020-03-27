//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ntru/NTRUEncryptionPrivateKeyParameters.java
//

#ifndef NTRUEncryptionPrivateKeyParameters_H
#define NTRUEncryptionPrivateKeyParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "NTRUEncryptionKeyParameters.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@class LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters;
@class LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;
@protocol LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial;

@interface LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters : LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionKeyParameters {
 @public
  id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> t_;
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *fp_;
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h_;
}

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)b
withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *)params;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)is
withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *)params;

- (instancetype __nonnull)initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)h
                              withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial:(id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>)t
                              withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)fp
                               withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *)params;

- (jboolean)isEqual:(id)obj;

- (IOSByteArray *)getEncoded;

- (NSUInteger)hash;

- (void)writeToWithJavaIoOutputStream:(JavaIoOutputStream *)os;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0
withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters)

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, t_, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, fp_, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters, h_, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> t, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *fp, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> t, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *fp, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h, id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> t, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *fp, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self, IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(IOSByteArray *b, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *self, JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters_initWithJavaIoInputStream_withLibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters_(JavaIoInputStream *is, LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoNtruNTRUEncryptionPrivateKeyParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NTRUEncryptionPrivateKeyParameters_H
