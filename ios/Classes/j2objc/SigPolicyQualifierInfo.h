//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/esf/SigPolicyQualifierInfo.java
//

#ifndef SigPolicyQualifierInfo_H
#define SigPolicyQualifierInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)sigPolicyQualifierId
                                     withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)sigQualifier;

+ (LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getSigPolicyQualifierId;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getSigQualifier;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sigPolicyQualifierId, id<LibOrgBouncycastleAsn1ASN1Encodable> sigQualifier);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *new_LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sigPolicyQualifierId, id<LibOrgBouncycastleAsn1ASN1Encodable> sigQualifier) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *create_LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *sigPolicyQualifierId, id<LibOrgBouncycastleAsn1ASN1Encodable> sigQualifier);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo *LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EsfSigPolicyQualifierInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SigPolicyQualifierInfo_H
