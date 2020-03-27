//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ess/SigningCertificateV2.java
//

#ifndef SigningCertificateV2_H
#define SigningCertificateV2_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1EssESSCertIDv2;

@interface LibOrgBouncycastleAsn1EssSigningCertificateV2 : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1Sequence *certs_;
  LibOrgBouncycastleAsn1ASN1Sequence *policies_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1EssESSCertIDv2:(LibOrgBouncycastleAsn1EssESSCertIDv2 *)cert;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1EssESSCertIDv2Array:(IOSObjectArray *)certs;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1EssESSCertIDv2Array:(IOSObjectArray *)certs
                       withLibOrgBouncycastleAsn1X509PolicyInformationArray:(IOSObjectArray *)policies;

- (IOSObjectArray *)getCerts;

+ (LibOrgBouncycastleAsn1EssSigningCertificateV2 *)getInstanceWithId:(id)o;

- (IOSObjectArray *)getPolicies;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EssSigningCertificateV2)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EssSigningCertificateV2, certs_, LibOrgBouncycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EssSigningCertificateV2, policies_, LibOrgBouncycastleAsn1ASN1Sequence *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssSigningCertificateV2 *LibOrgBouncycastleAsn1EssSigningCertificateV2_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EssSigningCertificateV2_initWithLibOrgBouncycastleAsn1EssESSCertIDv2_(LibOrgBouncycastleAsn1EssSigningCertificateV2 *self, LibOrgBouncycastleAsn1EssESSCertIDv2 *cert);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssSigningCertificateV2 *new_LibOrgBouncycastleAsn1EssSigningCertificateV2_initWithLibOrgBouncycastleAsn1EssESSCertIDv2_(LibOrgBouncycastleAsn1EssESSCertIDv2 *cert) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssSigningCertificateV2 *create_LibOrgBouncycastleAsn1EssSigningCertificateV2_initWithLibOrgBouncycastleAsn1EssESSCertIDv2_(LibOrgBouncycastleAsn1EssESSCertIDv2 *cert);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EssSigningCertificateV2_initWithLibOrgBouncycastleAsn1EssESSCertIDv2Array_(LibOrgBouncycastleAsn1EssSigningCertificateV2 *self, IOSObjectArray *certs);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssSigningCertificateV2 *new_LibOrgBouncycastleAsn1EssSigningCertificateV2_initWithLibOrgBouncycastleAsn1EssESSCertIDv2Array_(IOSObjectArray *certs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssSigningCertificateV2 *create_LibOrgBouncycastleAsn1EssSigningCertificateV2_initWithLibOrgBouncycastleAsn1EssESSCertIDv2Array_(IOSObjectArray *certs);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EssSigningCertificateV2_initWithLibOrgBouncycastleAsn1EssESSCertIDv2Array_withLibOrgBouncycastleAsn1X509PolicyInformationArray_(LibOrgBouncycastleAsn1EssSigningCertificateV2 *self, IOSObjectArray *certs, IOSObjectArray *policies);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssSigningCertificateV2 *new_LibOrgBouncycastleAsn1EssSigningCertificateV2_initWithLibOrgBouncycastleAsn1EssESSCertIDv2Array_withLibOrgBouncycastleAsn1X509PolicyInformationArray_(IOSObjectArray *certs, IOSObjectArray *policies) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssSigningCertificateV2 *create_LibOrgBouncycastleAsn1EssSigningCertificateV2_initWithLibOrgBouncycastleAsn1EssESSCertIDv2Array_withLibOrgBouncycastleAsn1X509PolicyInformationArray_(IOSObjectArray *certs, IOSObjectArray *policies);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EssSigningCertificateV2)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SigningCertificateV2_H
