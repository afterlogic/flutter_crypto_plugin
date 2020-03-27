//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/isismtt/ocsp/CertHash.java
//

#ifndef CertHash_H
#define CertHash_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1IsismttOcspCertHash : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)hashAlgorithm
                                                                  withByteArray:(IOSByteArray *)certificateHash;

- (IOSByteArray *)getCertificateHash;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getHashAlgorithm;

+ (LibOrgBouncycastleAsn1IsismttOcspCertHash *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1IsismttOcspCertHash)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttOcspCertHash *LibOrgBouncycastleAsn1IsismttOcspCertHash_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1IsismttOcspCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1IsismttOcspCertHash *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, IOSByteArray *certificateHash);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttOcspCertHash *new_LibOrgBouncycastleAsn1IsismttOcspCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, IOSByteArray *certificateHash) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1IsismttOcspCertHash *create_LibOrgBouncycastleAsn1IsismttOcspCertHash_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, IOSByteArray *certificateHash);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1IsismttOcspCertHash)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertHash_H
