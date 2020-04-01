//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmc/TaggedRequest.java
//

#ifndef TaggedRequest_H
#define TaggedRequest_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Choice.h"
#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmcTaggedCertificationRequest;
@class LibOrgBouncycastleAsn1CrmfCertReqMsg;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1CmcTaggedRequest : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1ASN1Choice >
@property (readonly, class) jint TCR NS_SWIFT_NAME(TCR);
@property (readonly, class) jint CRM NS_SWIFT_NAME(CRM);
@property (readonly, class) jint ORM NS_SWIFT_NAME(ORM);

+ (jint)TCR;

+ (jint)CRM;

+ (jint)ORM;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CrmfCertReqMsg:(LibOrgBouncycastleAsn1CrmfCertReqMsg *)crm;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmcTaggedCertificationRequest:(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *)tcr;

+ (LibOrgBouncycastleAsn1CmcTaggedRequest *)getInstanceWithId:(id)obj;

- (jint)getTagNo;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getValue;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmcTaggedRequest)

inline jint LibOrgBouncycastleAsn1CmcTaggedRequest_get_TCR(void);
#define LibOrgBouncycastleAsn1CmcTaggedRequest_TCR 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmcTaggedRequest, TCR, jint)

inline jint LibOrgBouncycastleAsn1CmcTaggedRequest_get_CRM(void);
#define LibOrgBouncycastleAsn1CmcTaggedRequest_CRM 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmcTaggedRequest, CRM, jint)

inline jint LibOrgBouncycastleAsn1CmcTaggedRequest_get_ORM(void);
#define LibOrgBouncycastleAsn1CmcTaggedRequest_ORM 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1CmcTaggedRequest, ORM, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmcTaggedRequest_initWithLibOrgBouncycastleAsn1CmcTaggedCertificationRequest_(LibOrgBouncycastleAsn1CmcTaggedRequest *self, LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *tcr);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedRequest *new_LibOrgBouncycastleAsn1CmcTaggedRequest_initWithLibOrgBouncycastleAsn1CmcTaggedCertificationRequest_(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *tcr) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedRequest *create_LibOrgBouncycastleAsn1CmcTaggedRequest_initWithLibOrgBouncycastleAsn1CmcTaggedCertificationRequest_(LibOrgBouncycastleAsn1CmcTaggedCertificationRequest *tcr);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmcTaggedRequest_initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_(LibOrgBouncycastleAsn1CmcTaggedRequest *self, LibOrgBouncycastleAsn1CrmfCertReqMsg *crm);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedRequest *new_LibOrgBouncycastleAsn1CmcTaggedRequest_initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_(LibOrgBouncycastleAsn1CrmfCertReqMsg *crm) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedRequest *create_LibOrgBouncycastleAsn1CmcTaggedRequest_initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_(LibOrgBouncycastleAsn1CrmfCertReqMsg *crm);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmcTaggedRequest *LibOrgBouncycastleAsn1CmcTaggedRequest_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmcTaggedRequest)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TaggedRequest_H