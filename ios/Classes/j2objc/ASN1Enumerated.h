//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1Enumerated.java
//

#ifndef ASN1Enumerated_H
#define ASN1Enumerated_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Primitive.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1OutputStream;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;

@interface LibOrgBouncycastleAsn1ASN1Enumerated : LibOrgBouncycastleAsn1ASN1Primitive

#pragma mark Public

- (instancetype __nonnull)initWithJavaMathBigInteger:(JavaMathBigInteger *)value;

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)bytes;

- (instancetype __nonnull)initWithInt:(jint)value;

+ (LibOrgBouncycastleAsn1ASN1Enumerated *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                    withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1ASN1Enumerated *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getValue;

- (NSUInteger)hash;

#pragma mark Package-Private

- (jboolean)asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)o;

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

+ (LibOrgBouncycastleAsn1ASN1Enumerated *)fromOctetStringWithByteArray:(IOSByteArray *)enc;

- (jboolean)isConstructed;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1ASN1Enumerated)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Enumerated *LibOrgBouncycastleAsn1ASN1Enumerated_getInstanceWithId_(id obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Enumerated *LibOrgBouncycastleAsn1ASN1Enumerated_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1Enumerated_initWithInt_(LibOrgBouncycastleAsn1ASN1Enumerated *self, jint value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Enumerated *new_LibOrgBouncycastleAsn1ASN1Enumerated_initWithInt_(jint value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Enumerated *create_LibOrgBouncycastleAsn1ASN1Enumerated_initWithInt_(jint value);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1Enumerated_initWithJavaMathBigInteger_(LibOrgBouncycastleAsn1ASN1Enumerated *self, JavaMathBigInteger *value);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Enumerated *new_LibOrgBouncycastleAsn1ASN1Enumerated_initWithJavaMathBigInteger_(JavaMathBigInteger *value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Enumerated *create_LibOrgBouncycastleAsn1ASN1Enumerated_initWithJavaMathBigInteger_(JavaMathBigInteger *value);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1Enumerated_initWithByteArray_(LibOrgBouncycastleAsn1ASN1Enumerated *self, IOSByteArray *bytes);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Enumerated *new_LibOrgBouncycastleAsn1ASN1Enumerated_initWithByteArray_(IOSByteArray *bytes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Enumerated *create_LibOrgBouncycastleAsn1ASN1Enumerated_initWithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Enumerated *LibOrgBouncycastleAsn1ASN1Enumerated_fromOctetStringWithByteArray_(IOSByteArray *enc);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ASN1Enumerated)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ASN1Enumerated_H
