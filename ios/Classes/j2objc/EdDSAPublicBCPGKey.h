//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/EdDSAPublicBCPGKey.java
//

#ifndef EdDSAPublicBCPGKey_H
#define EdDSAPublicBCPGKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECPublicBCPGKey.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleMathEcECPoint;

@interface LibOrgBouncycastleBcpgEdDSAPublicBCPGKey : LibOrgBouncycastleBcpgECPublicBCPGKey

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)encodedPoint;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                         withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)point;

#pragma mark Protected

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgEdDSAPublicBCPGKey)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgEdDSAPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgEdDSAPublicBCPGKey *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgEdDSAPublicBCPGKey *new_LibOrgBouncycastleBcpgEdDSAPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgEdDSAPublicBCPGKey *create_LibOrgBouncycastleBcpgEdDSAPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgEdDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleBcpgEdDSAPublicBCPGKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, LibOrgBouncycastleMathEcECPoint *point);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgEdDSAPublicBCPGKey *new_LibOrgBouncycastleBcpgEdDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, LibOrgBouncycastleMathEcECPoint *point) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgEdDSAPublicBCPGKey *create_LibOrgBouncycastleBcpgEdDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, LibOrgBouncycastleMathEcECPoint *point);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgEdDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_(LibOrgBouncycastleBcpgEdDSAPublicBCPGKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, JavaMathBigInteger *encodedPoint);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgEdDSAPublicBCPGKey *new_LibOrgBouncycastleBcpgEdDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, JavaMathBigInteger *encodedPoint) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgEdDSAPublicBCPGKey *create_LibOrgBouncycastleBcpgEdDSAPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withJavaMathBigInteger_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, JavaMathBigInteger *encodedPoint);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgEdDSAPublicBCPGKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // EdDSAPublicBCPGKey_H
