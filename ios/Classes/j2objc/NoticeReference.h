//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/NoticeReference.java
//

#ifndef NoticeReference_H
#define NoticeReference_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class JavaUtilVector;
@class LibOrgBouncycastleAsn1ASN1EncodableVector;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509DisplayText;

@interface LibOrgBouncycastleAsn1X509NoticeReference : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509DisplayText:(LibOrgBouncycastleAsn1X509DisplayText *)organization
                          withLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)noticeNumbers;

- (instancetype __nonnull)initWithNSString:(NSString *)organization
withLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)noticeNumbers;

- (instancetype __nonnull)initWithNSString:(NSString *)organization
                        withJavaUtilVector:(JavaUtilVector *)numbers;

+ (LibOrgBouncycastleAsn1X509NoticeReference *)getInstanceWithId:(id)as;

- (IOSObjectArray *)getNoticeNumbers;

- (LibOrgBouncycastleAsn1X509DisplayText *)getOrganization;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509NoticeReference)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509NoticeReference_initWithNSString_withJavaUtilVector_(LibOrgBouncycastleAsn1X509NoticeReference *self, NSString *organization, JavaUtilVector *numbers);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509NoticeReference *new_LibOrgBouncycastleAsn1X509NoticeReference_initWithNSString_withJavaUtilVector_(NSString *organization, JavaUtilVector *numbers) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509NoticeReference *create_LibOrgBouncycastleAsn1X509NoticeReference_initWithNSString_withJavaUtilVector_(NSString *organization, JavaUtilVector *numbers);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509NoticeReference_initWithNSString_withLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1X509NoticeReference *self, NSString *organization, LibOrgBouncycastleAsn1ASN1EncodableVector *noticeNumbers);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509NoticeReference *new_LibOrgBouncycastleAsn1X509NoticeReference_initWithNSString_withLibOrgBouncycastleAsn1ASN1EncodableVector_(NSString *organization, LibOrgBouncycastleAsn1ASN1EncodableVector *noticeNumbers) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509NoticeReference *create_LibOrgBouncycastleAsn1X509NoticeReference_initWithNSString_withLibOrgBouncycastleAsn1ASN1EncodableVector_(NSString *organization, LibOrgBouncycastleAsn1ASN1EncodableVector *noticeNumbers);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509NoticeReference_initWithLibOrgBouncycastleAsn1X509DisplayText_withLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1X509NoticeReference *self, LibOrgBouncycastleAsn1X509DisplayText *organization, LibOrgBouncycastleAsn1ASN1EncodableVector *noticeNumbers);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509NoticeReference *new_LibOrgBouncycastleAsn1X509NoticeReference_initWithLibOrgBouncycastleAsn1X509DisplayText_withLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1X509DisplayText *organization, LibOrgBouncycastleAsn1ASN1EncodableVector *noticeNumbers) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509NoticeReference *create_LibOrgBouncycastleAsn1X509NoticeReference_initWithLibOrgBouncycastleAsn1X509DisplayText_withLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1X509DisplayText *organization, LibOrgBouncycastleAsn1ASN1EncodableVector *noticeNumbers);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509NoticeReference *LibOrgBouncycastleAsn1X509NoticeReference_getInstanceWithId_(id as);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509NoticeReference)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NoticeReference_H