//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1BitString.java
//

#ifndef ASN1BitString_H
#define ASN1BitString_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Primitive.h"
#include "ASN1String.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class LibOrgBouncycastleAsn1ASN1OutputStream;

@interface LibOrgBouncycastleAsn1ASN1BitString : LibOrgBouncycastleAsn1ASN1Primitive < LibOrgBouncycastleAsn1ASN1String > {
 @public
  IOSByteArray *data_;
  jint padBits_;
}

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)data
                                    withInt:(jint)padBits;

- (IOSByteArray *)getBytes;

- (LibOrgBouncycastleAsn1ASN1Primitive *)getLoadedObject;

- (IOSByteArray *)getOctets;

- (jint)getPadBits;

- (NSString *)getString;

- (NSUInteger)hash;

- (jint)intValue;

- (NSString *)description;

#pragma mark Protected

- (jboolean)asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)o;

+ (IOSByteArray *)derFormWithByteArray:(IOSByteArray *)data
                               withInt:(jint)padBits;

+ (IOSByteArray *)getBytesWithInt:(jint)bitString;

+ (jint)getPadBitsWithInt:(jint)bitString;

#pragma mark Package-Private

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg;

+ (LibOrgBouncycastleAsn1ASN1BitString *)fromInputStreamWithInt:(jint)length
                                          withJavaIoInputStream:(JavaIoInputStream *)stream;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toDERObject;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toDLObject;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1ASN1BitString)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1ASN1BitString, data_, IOSByteArray *)

FOUNDATION_EXPORT jint LibOrgBouncycastleAsn1ASN1BitString_getPadBitsWithInt_(jint bitString);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleAsn1ASN1BitString_getBytesWithInt_(jint bitString);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1BitString_initWithByteArray_withInt_(LibOrgBouncycastleAsn1ASN1BitString *self, IOSByteArray *data, jint padBits);

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleAsn1ASN1BitString_derFormWithByteArray_withInt_(IOSByteArray *data, jint padBits);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1BitString *LibOrgBouncycastleAsn1ASN1BitString_fromInputStreamWithInt_withJavaIoInputStream_(jint length, JavaIoInputStream *stream);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ASN1BitString)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ASN1BitString_H
