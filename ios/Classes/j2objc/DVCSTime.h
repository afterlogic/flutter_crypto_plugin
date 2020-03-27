//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/dvcs/DVCSTime.java
//

#ifndef DVCSTime_H
#define DVCSTime_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class JavaUtilDate;
@class LibOrgBouncycastleAsn1ASN1GeneralizedTime;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo;

@interface LibOrgBouncycastleAsn1DvcsDVCSTime : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo:(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)timeStampToken;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)genTime;

- (instancetype __nonnull)initWithJavaUtilDate:(JavaUtilDate *)time;

- (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getGenTime;

+ (LibOrgBouncycastleAsn1DvcsDVCSTime *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                  withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1DvcsDVCSTime *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *)getTimeStampToken;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DvcsDVCSTime)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsDVCSTime_initWithJavaUtilDate_(LibOrgBouncycastleAsn1DvcsDVCSTime *self, JavaUtilDate *time);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSTime *new_LibOrgBouncycastleAsn1DvcsDVCSTime_initWithJavaUtilDate_(JavaUtilDate *time) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSTime *create_LibOrgBouncycastleAsn1DvcsDVCSTime_initWithJavaUtilDate_(JavaUtilDate *time);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsDVCSTime_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1DvcsDVCSTime *self, LibOrgBouncycastleAsn1ASN1GeneralizedTime *genTime);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSTime *new_LibOrgBouncycastleAsn1DvcsDVCSTime_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *genTime) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSTime *create_LibOrgBouncycastleAsn1DvcsDVCSTime_initWithLibOrgBouncycastleAsn1ASN1GeneralizedTime_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *genTime);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DvcsDVCSTime_initWithLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1DvcsDVCSTime *self, LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStampToken);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSTime *new_LibOrgBouncycastleAsn1DvcsDVCSTime_initWithLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStampToken) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSTime *create_LibOrgBouncycastleAsn1DvcsDVCSTime_initWithLibOrgBouncycastleAsn1CmsAsn1CmsContentInfo_(LibOrgBouncycastleAsn1CmsAsn1CmsContentInfo *timeStampToken);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSTime *LibOrgBouncycastleAsn1DvcsDVCSTime_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DvcsDVCSTime *LibOrgBouncycastleAsn1DvcsDVCSTime_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DvcsDVCSTime)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DVCSTime_H
