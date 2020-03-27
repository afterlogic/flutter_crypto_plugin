//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/mozilla/SignedPublicKeyAndChallenge.java
//

#ifndef SignedPublicKeyAndChallenge_H
#define SignedPublicKeyAndChallenge_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1DERBitString;
@class LibOrgBouncycastleAsn1MozillaPublicKeyAndChallenge;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1MozillaSignedPublicKeyAndChallenge : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

+ (LibOrgBouncycastleAsn1MozillaSignedPublicKeyAndChallenge *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1MozillaPublicKeyAndChallenge *)getPublicKeyAndChallenge;

- (LibOrgBouncycastleAsn1DERBitString *)getSignature;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getSignatureAlgorithm;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1MozillaSignedPublicKeyAndChallenge)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1MozillaSignedPublicKeyAndChallenge *LibOrgBouncycastleAsn1MozillaSignedPublicKeyAndChallenge_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1MozillaSignedPublicKeyAndChallenge)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SignedPublicKeyAndChallenge_H
