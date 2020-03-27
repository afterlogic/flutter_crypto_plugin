//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x9/KeySpecificInfo.java
//

#ifndef KeySpecificInfo_H
#define KeySpecificInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1X9KeySpecificInfo : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)algorithm
                                   withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)counter;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getAlgorithm;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getCounter;

+ (LibOrgBouncycastleAsn1X9KeySpecificInfo *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X9KeySpecificInfo)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X9KeySpecificInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1X9KeySpecificInfo *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algorithm, LibOrgBouncycastleAsn1ASN1OctetString *counter);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9KeySpecificInfo *new_LibOrgBouncycastleAsn1X9KeySpecificInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algorithm, LibOrgBouncycastleAsn1ASN1OctetString *counter) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9KeySpecificInfo *create_LibOrgBouncycastleAsn1X9KeySpecificInfo_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *algorithm, LibOrgBouncycastleAsn1ASN1OctetString *counter);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9KeySpecificInfo *LibOrgBouncycastleAsn1X9KeySpecificInfo_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X9KeySpecificInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeySpecificInfo_H