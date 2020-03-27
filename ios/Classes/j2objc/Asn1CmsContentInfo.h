//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/Asn1CmsContentInfo.java
//

#ifndef Asn1CmsContentInfo_H
#define Asn1CmsContentInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "CMSObjectIdentifiers.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1CmsCMSObjectIdentifiers >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)contentType
                                     withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)content;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getContent;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getContentType;

+ (LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                           withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *new_LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *create_LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *contentType, id<LibOrgBouncycastleAsn1ASN1Encodable> content);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *new_LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *contentType, id<LibOrgBouncycastleAsn1ASN1Encodable> content) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *create_LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *contentType, id<LibOrgBouncycastleAsn1ASN1Encodable> content);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Asn1CmsContentInfo_H
