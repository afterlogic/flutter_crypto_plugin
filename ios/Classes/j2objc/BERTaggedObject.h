//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/BERTaggedObject.java
//

#ifndef BERTaggedObject_H
#define BERTaggedObject_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1TaggedObject.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1OutputStream;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1BERTaggedObject : LibOrgBouncycastleAsn1ASN1TaggedObject

#pragma mark Public

- (instancetype __nonnull)initWithBoolean:(jboolean)explicit_
                                  withInt:(jint)tagNo
  withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

- (instancetype __nonnull)initWithInt:(jint)tagNo;

- (instancetype __nonnull)initWithInt:(jint)tagNo
withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

#pragma mark Package-Private

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg;

- (jint)encodedLength;

- (jboolean)isConstructed;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1BERTaggedObject)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1BERTaggedObject *self, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERTaggedObject *new_LibOrgBouncycastleAsn1BERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERTaggedObject *create_LibOrgBouncycastleAsn1BERTaggedObject_initWithInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1BERTaggedObject *self, jboolean explicit_, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERTaggedObject *new_LibOrgBouncycastleAsn1BERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jboolean explicit_, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERTaggedObject *create_LibOrgBouncycastleAsn1BERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(jboolean explicit_, jint tagNo, id<LibOrgBouncycastleAsn1ASN1Encodable> obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BERTaggedObject_initWithInt_(LibOrgBouncycastleAsn1BERTaggedObject *self, jint tagNo);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERTaggedObject *new_LibOrgBouncycastleAsn1BERTaggedObject_initWithInt_(jint tagNo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BERTaggedObject *create_LibOrgBouncycastleAsn1BERTaggedObject_initWithInt_(jint tagNo);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1BERTaggedObject)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BERTaggedObject_H