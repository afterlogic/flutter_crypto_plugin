//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/OtherName.java
//

#ifndef OtherName_H
#define OtherName_H

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

@interface LibOrgBouncycastleAsn1X509OtherName : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)typeID
                                     withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)value;

+ (LibOrgBouncycastleAsn1X509OtherName *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getTypeID;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getValue;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509OtherName)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509OtherName *LibOrgBouncycastleAsn1X509OtherName_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509OtherName_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1X509OtherName *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *typeID, id<LibOrgBouncycastleAsn1ASN1Encodable> value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509OtherName *new_LibOrgBouncycastleAsn1X509OtherName_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *typeID, id<LibOrgBouncycastleAsn1ASN1Encodable> value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509OtherName *create_LibOrgBouncycastleAsn1X509OtherName_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *typeID, id<LibOrgBouncycastleAsn1ASN1Encodable> value);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509OtherName)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OtherName_H
