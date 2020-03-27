//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/LazyEncodedSequence.java
//

#ifndef LazyEncodedSequence_H
#define LazyEncodedSequence_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Sequence.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1EncodableVector;
@class LibOrgBouncycastleAsn1ASN1OutputStream;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@protocol JavaUtilEnumeration;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1LazyEncodedSequence : LibOrgBouncycastleAsn1ASN1Sequence

#pragma mark Public

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getObjectAtWithInt:(jint)index;

- (id<JavaUtilEnumeration>)getObjects;

- (jint)size;

#pragma mark Package-Private

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encoded;

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toDERObject;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toDLObject;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1EncodableArray:(IOSObjectArray *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1LazyEncodedSequence)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1LazyEncodedSequence_initWithByteArray_(LibOrgBouncycastleAsn1LazyEncodedSequence *self, IOSByteArray *encoded);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1LazyEncodedSequence *new_LibOrgBouncycastleAsn1LazyEncodedSequence_initWithByteArray_(IOSByteArray *encoded) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1LazyEncodedSequence *create_LibOrgBouncycastleAsn1LazyEncodedSequence_initWithByteArray_(IOSByteArray *encoded);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1LazyEncodedSequence)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // LazyEncodedSequence_H