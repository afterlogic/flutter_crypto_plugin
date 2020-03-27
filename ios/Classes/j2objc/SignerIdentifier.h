//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/SignerIdentifier.java
//

#ifndef SignerIdentifier_H
#define SignerIdentifier_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1CmsSignerIdentifier : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber:(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *)id_;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)id_;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)id_;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getId;

+ (LibOrgBouncycastleAsn1CmsSignerIdentifier *)getInstanceWithId:(id)o;

- (jboolean)isTagged;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmsSignerIdentifier)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsSignerIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(LibOrgBouncycastleAsn1CmsSignerIdentifier *self, LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *id_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsSignerIdentifier *new_LibOrgBouncycastleAsn1CmsSignerIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *id_) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsSignerIdentifier *create_LibOrgBouncycastleAsn1CmsSignerIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *id_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsSignerIdentifier_initWithLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1CmsSignerIdentifier *self, LibOrgBouncycastleAsn1ASN1OctetString *id_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsSignerIdentifier *new_LibOrgBouncycastleAsn1CmsSignerIdentifier_initWithLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1OctetString *id_) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsSignerIdentifier *create_LibOrgBouncycastleAsn1CmsSignerIdentifier_initWithLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1OctetString *id_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsSignerIdentifier_initWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1CmsSignerIdentifier *self, LibOrgBouncycastleAsn1ASN1Primitive *id_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsSignerIdentifier *new_LibOrgBouncycastleAsn1CmsSignerIdentifier_initWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1ASN1Primitive *id_) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsSignerIdentifier *create_LibOrgBouncycastleAsn1CmsSignerIdentifier_initWithLibOrgBouncycastleAsn1ASN1Primitive_(LibOrgBouncycastleAsn1ASN1Primitive *id_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsSignerIdentifier *LibOrgBouncycastleAsn1CmsSignerIdentifier_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmsSignerIdentifier)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SignerIdentifier_H
