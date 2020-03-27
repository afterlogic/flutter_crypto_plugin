//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DERBitString.java
//

#ifndef DERBitString_H
#define DERBitString_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1BitString.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleAsn1ASN1OutputStream;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1DERBitString : LibOrgBouncycastleAsn1ASN1BitString

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)data;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)data
                                    withInt:(jint)padBits;

- (instancetype __nonnull)initWithInt:(jint)value;

+ (LibOrgBouncycastleAsn1DERBitString *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                  withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1DERBitString *)getInstanceWithId:(id)obj;

#pragma mark Protected

- (instancetype __nonnull)initWithByte:(jbyte)data
                               withInt:(jint)padBits;

#pragma mark Package-Private

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

+ (LibOrgBouncycastleAsn1DERBitString *)fromOctetStringWithByteArray:(IOSByteArray *)bytes;

- (jboolean)isConstructed;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1DERBitString)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *LibOrgBouncycastleAsn1DERBitString_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *LibOrgBouncycastleAsn1DERBitString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERBitString_initWithByte_withInt_(LibOrgBouncycastleAsn1DERBitString *self, jbyte data, jint padBits);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *new_LibOrgBouncycastleAsn1DERBitString_initWithByte_withInt_(jbyte data, jint padBits) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *create_LibOrgBouncycastleAsn1DERBitString_initWithByte_withInt_(jbyte data, jint padBits);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERBitString_initWithByteArray_withInt_(LibOrgBouncycastleAsn1DERBitString *self, IOSByteArray *data, jint padBits);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *new_LibOrgBouncycastleAsn1DERBitString_initWithByteArray_withInt_(IOSByteArray *data, jint padBits) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *create_LibOrgBouncycastleAsn1DERBitString_initWithByteArray_withInt_(IOSByteArray *data, jint padBits);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERBitString_initWithByteArray_(LibOrgBouncycastleAsn1DERBitString *self, IOSByteArray *data);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *new_LibOrgBouncycastleAsn1DERBitString_initWithByteArray_(IOSByteArray *data) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *create_LibOrgBouncycastleAsn1DERBitString_initWithByteArray_(IOSByteArray *data);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERBitString_initWithInt_(LibOrgBouncycastleAsn1DERBitString *self, jint value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *new_LibOrgBouncycastleAsn1DERBitString_initWithInt_(jint value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *create_LibOrgBouncycastleAsn1DERBitString_initWithInt_(jint value);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DERBitString_initWithLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1DERBitString *self, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *new_LibOrgBouncycastleAsn1DERBitString_initWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *create_LibOrgBouncycastleAsn1DERBitString_initWithLibOrgBouncycastleAsn1ASN1Encodable_(id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DERBitString *LibOrgBouncycastleAsn1DERBitString_fromOctetStringWithByteArray_(IOSByteArray *bytes);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DERBitString)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DERBitString_H
