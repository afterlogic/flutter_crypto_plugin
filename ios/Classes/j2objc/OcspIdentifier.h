//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/OcspIdentifier.java
//

#ifndef OcspIdentifier_H
#define OcspIdentifier_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1GeneralizedTime;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1OcspResponderID;

@interface LibOrgBouncycastleAsn1EsfOcspIdentifier : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1OcspResponderID:(LibOrgBouncycastleAsn1OcspResponderID *)ocspResponderID
                          withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)producedAt;

+ (LibOrgBouncycastleAsn1EsfOcspIdentifier *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1OcspResponderID *)getOcspResponderID;

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getProducedAt;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EsfOcspIdentifier)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfOcspIdentifier *LibOrgBouncycastleAsn1EsfOcspIdentifier_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1OcspResponderID_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1EsfOcspIdentifier *self, LibOrgBouncycastleAsn1OcspResponderID *ocspResponderID, LibOrgBouncycastleAsn1ASN1GeneralizedTime *producedAt);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfOcspIdentifier *new_LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1OcspResponderID_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1OcspResponderID *ocspResponderID, LibOrgBouncycastleAsn1ASN1GeneralizedTime *producedAt) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfOcspIdentifier *create_LibOrgBouncycastleAsn1EsfOcspIdentifier_initWithLibOrgBouncycastleAsn1OcspResponderID_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1OcspResponderID *ocspResponderID, LibOrgBouncycastleAsn1ASN1GeneralizedTime *producedAt);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EsfOcspIdentifier)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OcspIdentifier_H