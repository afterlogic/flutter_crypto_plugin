//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/crmf/CertReqMessages.java
//

#ifndef CertReqMessages_H
#define CertReqMessages_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CrmfCertReqMsg;

@interface LibOrgBouncycastleAsn1CrmfCertReqMessages : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CrmfCertReqMsg:(LibOrgBouncycastleAsn1CrmfCertReqMsg *)msg;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray:(IOSObjectArray *)msgs;

+ (LibOrgBouncycastleAsn1CrmfCertReqMessages *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

- (IOSObjectArray *)toCertReqMsgArray;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CrmfCertReqMessages)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfCertReqMessages *LibOrgBouncycastleAsn1CrmfCertReqMessages_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_(LibOrgBouncycastleAsn1CrmfCertReqMessages *self, LibOrgBouncycastleAsn1CrmfCertReqMsg *msg);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfCertReqMessages *new_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_(LibOrgBouncycastleAsn1CrmfCertReqMsg *msg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfCertReqMessages *create_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsg_(LibOrgBouncycastleAsn1CrmfCertReqMsg *msg);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray_(LibOrgBouncycastleAsn1CrmfCertReqMessages *self, IOSObjectArray *msgs);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfCertReqMessages *new_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray_(IOSObjectArray *msgs) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfCertReqMessages *create_LibOrgBouncycastleAsn1CrmfCertReqMessages_initWithLibOrgBouncycastleAsn1CrmfCertReqMsgArray_(IOSObjectArray *msgs);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CrmfCertReqMessages)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertReqMessages_H