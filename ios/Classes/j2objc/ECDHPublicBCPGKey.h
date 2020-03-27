//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/ECDHPublicBCPGKey.java
//

#ifndef ECDHPublicBCPGKey_H
#define ECDHPublicBCPGKey_H

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
@class LibOrgBouncycastleBcpgBCPGOutputStream;
@class LibOrgBouncycastleMathEcECPoint;

@interface LibOrgBouncycastleBcpgECDHPublicBCPGKey : LibOrgBouncycastleBcpgECPublicBCPGKey

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                         withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)point
                                                                     withInt:(jint)hashAlgorithm
                                                                     withInt:(jint)symmetricKeyAlgorithm;

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg;

- (jbyte)getHashAlgorithm;

- (jbyte)getReserved;

- (jbyte)getSymmetricKeyAlgorithm;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg0
                                                      withJavaMathBigInteger:(JavaMathBigInteger *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)arg0
                                         withLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgECDHPublicBCPGKey)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgECDHPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgECDHPublicBCPGKey *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgECDHPublicBCPGKey *new_LibOrgBouncycastleBcpgECDHPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgECDHPublicBCPGKey *create_LibOrgBouncycastleBcpgECDHPublicBCPGKey_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgECDHPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_withInt_withInt_(LibOrgBouncycastleBcpgECDHPublicBCPGKey *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, LibOrgBouncycastleMathEcECPoint *point, jint hashAlgorithm, jint symmetricKeyAlgorithm);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgECDHPublicBCPGKey *new_LibOrgBouncycastleBcpgECDHPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_withInt_withInt_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, LibOrgBouncycastleMathEcECPoint *point, jint hashAlgorithm, jint symmetricKeyAlgorithm) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgECDHPublicBCPGKey *create_LibOrgBouncycastleBcpgECDHPublicBCPGKey_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleMathEcECPoint_withInt_withInt_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *oid, LibOrgBouncycastleMathEcECPoint *point, jint hashAlgorithm, jint symmetricKeyAlgorithm);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgECDHPublicBCPGKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECDHPublicBCPGKey_H
