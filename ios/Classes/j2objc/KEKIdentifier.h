//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/KEKIdentifier.java
//

#ifndef KEKIdentifier_H
#define KEKIdentifier_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1GeneralizedTime;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CmsOtherKeyAttribute;

@interface LibOrgBouncycastleAsn1CmsKEKIdentifier : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)keyIdentifier
withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)date
withLibOrgBouncycastleAsn1CmsOtherKeyAttribute:(LibOrgBouncycastleAsn1CmsOtherKeyAttribute *)other;

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getDate;

+ (LibOrgBouncycastleAsn1CmsKEKIdentifier *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1CmsKEKIdentifier *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getKeyIdentifier;

- (LibOrgBouncycastleAsn1CmsOtherKeyAttribute *)getOther;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmsKEKIdentifier)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsKEKIdentifier_initWithByteArray_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(LibOrgBouncycastleAsn1CmsKEKIdentifier *self, IOSByteArray *keyIdentifier, LibOrgBouncycastleAsn1ASN1GeneralizedTime *date, LibOrgBouncycastleAsn1CmsOtherKeyAttribute *other);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKEKIdentifier *new_LibOrgBouncycastleAsn1CmsKEKIdentifier_initWithByteArray_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(IOSByteArray *keyIdentifier, LibOrgBouncycastleAsn1ASN1GeneralizedTime *date, LibOrgBouncycastleAsn1CmsOtherKeyAttribute *other) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKEKIdentifier *create_LibOrgBouncycastleAsn1CmsKEKIdentifier_initWithByteArray_withLibOrgBouncycastleAsn1ASN1GeneralizedTime_withLibOrgBouncycastleAsn1CmsOtherKeyAttribute_(IOSByteArray *keyIdentifier, LibOrgBouncycastleAsn1ASN1GeneralizedTime *date, LibOrgBouncycastleAsn1CmsOtherKeyAttribute *other);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKEKIdentifier *LibOrgBouncycastleAsn1CmsKEKIdentifier_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsKEKIdentifier *LibOrgBouncycastleAsn1CmsKEKIdentifier_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmsKEKIdentifier)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KEKIdentifier_H
