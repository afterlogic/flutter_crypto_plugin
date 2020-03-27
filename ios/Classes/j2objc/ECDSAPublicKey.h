//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/eac/ECDSAPublicKey.java
//

#ifndef ECDSAPublicKey_H
#define ECDSAPublicKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PublicKeyDataObject.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1EncodableVector;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;

@interface LibOrgBouncycastleAsn1EacECDSAPublicKey : LibOrgBouncycastleAsn1EacPublicKeyDataObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)usage
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)p
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)a
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)b
                                                               withByteArray:(IOSByteArray *)basePoint
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)order
                                                               withByteArray:(IOSByteArray *)publicPoint
                                                                     withInt:(jint)cofactor;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)usage
                                                               withByteArray:(IOSByteArray *)ppY;

- (LibOrgBouncycastleAsn1ASN1EncodableVector *)getASN1EncodableVectorWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                                                                        withBoolean:(jboolean)publicPointOnly;

- (IOSByteArray *)getBasePointG;

- (JavaMathBigInteger *)getCofactorF;

- (JavaMathBigInteger *)getFirstCoefA;

- (JavaMathBigInteger *)getOrderOfBasePointR;

- (JavaMathBigInteger *)getPrimeModulusP;

- (IOSByteArray *)getPublicPointY;

- (JavaMathBigInteger *)getSecondCoefB;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getUsage;

- (jboolean)hasParameters;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EacECDSAPublicKey)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EacECDSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1EacECDSAPublicKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacECDSAPublicKey *new_LibOrgBouncycastleAsn1EacECDSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacECDSAPublicKey *create_LibOrgBouncycastleAsn1EacECDSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EacECDSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(LibOrgBouncycastleAsn1EacECDSAPublicKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *usage, IOSByteArray *ppY);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacECDSAPublicKey *new_LibOrgBouncycastleAsn1EacECDSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *usage, IOSByteArray *ppY) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacECDSAPublicKey *create_LibOrgBouncycastleAsn1EacECDSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *usage, IOSByteArray *ppY);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EacECDSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withJavaMathBigInteger_withByteArray_withInt_(LibOrgBouncycastleAsn1EacECDSAPublicKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *usage, JavaMathBigInteger *p, JavaMathBigInteger *a, JavaMathBigInteger *b, IOSByteArray *basePoint, JavaMathBigInteger *order, IOSByteArray *publicPoint, jint cofactor);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacECDSAPublicKey *new_LibOrgBouncycastleAsn1EacECDSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withJavaMathBigInteger_withByteArray_withInt_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *usage, JavaMathBigInteger *p, JavaMathBigInteger *a, JavaMathBigInteger *b, IOSByteArray *basePoint, JavaMathBigInteger *order, IOSByteArray *publicPoint, jint cofactor) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EacECDSAPublicKey *create_LibOrgBouncycastleAsn1EacECDSAPublicKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_withJavaMathBigInteger_withByteArray_withInt_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *usage, JavaMathBigInteger *p, JavaMathBigInteger *a, JavaMathBigInteger *b, IOSByteArray *basePoint, JavaMathBigInteger *order, IOSByteArray *publicPoint, jint cofactor);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EacECDSAPublicKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECDSAPublicKey_H
