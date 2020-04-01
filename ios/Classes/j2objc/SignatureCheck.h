//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/bc/SignatureCheck.java
//

#ifndef SignatureCheck_H
#define SignatureCheck_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1BitString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1BcSignatureCheck : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)signatureAlgorithm
                                                                  withByteArray:(IOSByteArray *)signature;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)signatureAlgorithm
                             withLibOrgBouncycastleAsn1X509X509CertificateArray:(IOSObjectArray *)certificates
                                                                  withByteArray:(IOSByteArray *)signature;

- (IOSObjectArray *)getCertificates;

+ (LibOrgBouncycastleAsn1BcSignatureCheck *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1BitString *)getSignature;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getSignatureAlgorithm;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1BcSignatureCheck)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BcSignatureCheck_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1BcSignatureCheck *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, IOSByteArray *signature);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcSignatureCheck *new_LibOrgBouncycastleAsn1BcSignatureCheck_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, IOSByteArray *signature) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcSignatureCheck *create_LibOrgBouncycastleAsn1BcSignatureCheck_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, IOSByteArray *signature);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BcSignatureCheck_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509X509CertificateArray_withByteArray_(LibOrgBouncycastleAsn1BcSignatureCheck *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, IOSObjectArray *certificates, IOSByteArray *signature);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcSignatureCheck *new_LibOrgBouncycastleAsn1BcSignatureCheck_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509X509CertificateArray_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, IOSObjectArray *certificates, IOSByteArray *signature) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcSignatureCheck *create_LibOrgBouncycastleAsn1BcSignatureCheck_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509X509CertificateArray_withByteArray_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signatureAlgorithm, IOSObjectArray *certificates, IOSByteArray *signature);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcSignatureCheck *LibOrgBouncycastleAsn1BcSignatureCheck_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1BcSignatureCheck)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SignatureCheck_H