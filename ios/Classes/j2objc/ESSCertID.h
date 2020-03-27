//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ess/ESSCertID.java
//

#ifndef ESSCertID_H
#define ESSCertID_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1X509IssuerSerial;

@interface LibOrgBouncycastleAsn1EssESSCertID : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)hash_;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)hash_
 withLibOrgBouncycastleAsn1X509IssuerSerial:(LibOrgBouncycastleAsn1X509IssuerSerial *)issuerSerial;

- (IOSByteArray *)getCertHash;

+ (LibOrgBouncycastleAsn1EssESSCertID *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1X509IssuerSerial *)getIssuerSerial;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1EssESSCertID)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertID *LibOrgBouncycastleAsn1EssESSCertID_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EssESSCertID_initWithByteArray_(LibOrgBouncycastleAsn1EssESSCertID *self, IOSByteArray *hash_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertID *new_LibOrgBouncycastleAsn1EssESSCertID_initWithByteArray_(IOSByteArray *hash_) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertID *create_LibOrgBouncycastleAsn1EssESSCertID_initWithByteArray_(IOSByteArray *hash_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1EssESSCertID_initWithByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(LibOrgBouncycastleAsn1EssESSCertID *self, IOSByteArray *hash_, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertID *new_LibOrgBouncycastleAsn1EssESSCertID_initWithByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(IOSByteArray *hash_, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1EssESSCertID *create_LibOrgBouncycastleAsn1EssESSCertID_initWithByteArray_withLibOrgBouncycastleAsn1X509IssuerSerial_(IOSByteArray *hash_, LibOrgBouncycastleAsn1X509IssuerSerial *issuerSerial);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1EssESSCertID)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ESSCertID_H