//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/eac/Asn1EacRSAPublicKey.java
//

#ifndef Asn1EacRSAPublicKey_H
#define Asn1EacRSAPublicKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PublicKeyDataObject.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;

@interface LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey : LibOrgBouncycastleAsn1EacPublicKeyDataObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)usage
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)modulus
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)exponent;

- (JavaMathBigInteger *)getModulus;

- (JavaMathBigInteger *)getPublicExponent;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getUsage;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey *new_LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey *create_LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *usage, JavaMathBigInteger *modulus, JavaMathBigInteger *exponent);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey *new_LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *usage, JavaMathBigInteger *modulus, JavaMathBigInteger *exponent) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey *create_LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_withJavaMathBigInteger_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *usage, JavaMathBigInteger *modulus, JavaMathBigInteger *exponent);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EacAsn1EacRSAPublicKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Asn1EacRSAPublicKey_H