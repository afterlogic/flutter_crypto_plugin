//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/KeyAgreeRecipientIdentifier.java
//

#ifndef KeyAgreeRecipientIdentifier_H
#define KeyAgreeRecipientIdentifier_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber;
@class LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier;

@interface LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber:(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *)issuerSerial;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier:(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *)rKeyID;

+ (LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                                    withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *)getIssuerAndSerialNumber;

- (LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *)getRKeyID;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *self, LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *issuerSerial);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *new_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *issuerSerial) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *create_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *issuerSerial);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *self, LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *rKeyID);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *new_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *rKeyID) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier *create_LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier_initWithLibOrgBouncycastleAsn1CmsRecipientKeyIdentifier_(LibOrgBouncycastleAsn1CmsRecipientKeyIdentifier *rKeyID);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmsKeyAgreeRecipientIdentifier)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyAgreeRecipientIdentifier_H