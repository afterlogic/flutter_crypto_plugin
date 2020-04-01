//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/crmf/DhSigStatic.java
//

#ifndef DhSigStatic_H
#define DhSigStatic_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber;

@interface LibOrgBouncycastleAsn1CrmfDhSigStatic : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber:(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *)issuerAndSerial
                                                                          withByteArray:(IOSByteArray *)hashValue;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)hashValue;

- (IOSByteArray *)getHashValue;

+ (LibOrgBouncycastleAsn1CrmfDhSigStatic *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *)getIssuerAndSerial;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CrmfDhSigStatic)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CrmfDhSigStatic_initWithByteArray_(LibOrgBouncycastleAsn1CrmfDhSigStatic *self, IOSByteArray *hashValue);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfDhSigStatic *new_LibOrgBouncycastleAsn1CrmfDhSigStatic_initWithByteArray_(IOSByteArray *hashValue) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfDhSigStatic *create_LibOrgBouncycastleAsn1CrmfDhSigStatic_initWithByteArray_(IOSByteArray *hashValue);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CrmfDhSigStatic_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_withByteArray_(LibOrgBouncycastleAsn1CrmfDhSigStatic *self, LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *issuerAndSerial, IOSByteArray *hashValue);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfDhSigStatic *new_LibOrgBouncycastleAsn1CrmfDhSigStatic_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_withByteArray_(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *issuerAndSerial, IOSByteArray *hashValue) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfDhSigStatic *create_LibOrgBouncycastleAsn1CrmfDhSigStatic_initWithLibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber_withByteArray_(LibOrgBouncycastleAsn1CmsAsn1CmsIssuerAndSerialNumber *issuerAndSerial, IOSByteArray *hashValue);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CrmfDhSigStatic *LibOrgBouncycastleAsn1CrmfDhSigStatic_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CrmfDhSigStatic)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DhSigStatic_H