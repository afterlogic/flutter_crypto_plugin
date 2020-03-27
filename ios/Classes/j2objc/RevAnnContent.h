//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/RevAnnContent.java
//

#ifndef RevAnnContent_H
#define RevAnnContent_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1GeneralizedTime;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmpPKIStatus;
@class LibOrgBouncycastleAsn1CrmfCertId;
@class LibOrgBouncycastleAsn1X509Extensions;

@interface LibOrgBouncycastleAsn1CmpRevAnnContent : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getBadSinceDate;

- (LibOrgBouncycastleAsn1CrmfCertId *)getCertId;

- (LibOrgBouncycastleAsn1X509Extensions *)getCrlDetails;

+ (LibOrgBouncycastleAsn1CmpRevAnnContent *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1CmpPKIStatus *)getStatus;

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getWillBeRevokedAt;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpRevAnnContent)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpRevAnnContent *LibOrgBouncycastleAsn1CmpRevAnnContent_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpRevAnnContent)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RevAnnContent_H
