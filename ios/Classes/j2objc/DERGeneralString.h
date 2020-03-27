//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DERGeneralString.java
//

#ifndef DERGeneralString_H
#define DERGeneralString_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Primitive.h"
#include "ASN1String.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1OutputStream;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;

@interface LibOrgBouncycastleAsn1DERGeneralString : LibOrgBouncycastleAsn1ASN1Primitive < LibOrgBouncycastleAsn1ASN1String >

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)string;

+ (LibOrgBouncycastleAsn1DERGeneralString *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1DERGeneralString *)getInstanceWithId:(id)obj;

- (IOSByteArray *)getOctets;

- (NSString *)getString;

- (NSUInteger)hash;

- (NSString *)description;

#pragma mark Package-Private

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)string;

- (jboolean)asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)o;

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

- (jboolean)isConstructed;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DERGeneralString)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERGeneralString *LibOrgBouncycastleAsn1DERGeneralString_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERGeneralString *LibOrgBouncycastleAsn1DERGeneralString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERGeneralString_initWithByteArray_(LibOrgBouncycastleAsn1DERGeneralString *self, IOSByteArray *string);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERGeneralString *new_LibOrgBouncycastleAsn1DERGeneralString_initWithByteArray_(IOSByteArray *string) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERGeneralString *create_LibOrgBouncycastleAsn1DERGeneralString_initWithByteArray_(IOSByteArray *string);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERGeneralString_initWithNSString_(LibOrgBouncycastleAsn1DERGeneralString *self, NSString *string);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERGeneralString *new_LibOrgBouncycastleAsn1DERGeneralString_initWithNSString_(NSString *string) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERGeneralString *create_LibOrgBouncycastleAsn1DERGeneralString_initWithNSString_(NSString *string);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DERGeneralString)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DERGeneralString_H
