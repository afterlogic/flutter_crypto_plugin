//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cms/TimeStampTokenEvidence.java
//

#ifndef TimeStampTokenEvidence_H
#define TimeStampTokenEvidence_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CmsTimeStampAndCRL;

@interface LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL:(LibOrgBouncycastleAsn1CmsTimeStampAndCRL *)timeStampAndCRL;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray:(IOSObjectArray *)timeStampAndCRLs;

+ (LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)tagged
                                                                                               withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (IOSObjectArray *)toTimeStampAndCRLArray;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *self, IOSObjectArray *timeStampAndCRLs);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *new_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(IOSObjectArray *timeStampAndCRLs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *create_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRLArray_(IOSObjectArray *timeStampAndCRLs);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL_(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *self, LibOrgBouncycastleAsn1CmsTimeStampAndCRL *timeStampAndCRL);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *new_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL_(LibOrgBouncycastleAsn1CmsTimeStampAndCRL *timeStampAndCRL) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *create_LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_initWithLibOrgBouncycastleAsn1CmsTimeStampAndCRL_(LibOrgBouncycastleAsn1CmsTimeStampAndCRL *timeStampAndCRL);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *tagged, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence *LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmsTimeStampTokenEvidence)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TimeStampTokenEvidence_H
