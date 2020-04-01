//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1EncodableVector.java
//

#ifndef ASN1EncodableVector_H
#define ASN1EncodableVector_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleAsn1ASN1EncodableVector : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (void)addWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)obj;

- (void)addAllWithLibOrgBouncycastleAsn1ASN1EncodableVector:(LibOrgBouncycastleAsn1ASN1EncodableVector *)other;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getWithInt:(jint)i;

- (jint)size;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1ASN1EncodableVector)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1ASN1EncodableVector_init(LibOrgBouncycastleAsn1ASN1EncodableVector *self);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1EncodableVector *new_LibOrgBouncycastleAsn1ASN1EncodableVector_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1EncodableVector *create_LibOrgBouncycastleAsn1ASN1EncodableVector_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1ASN1EncodableVector)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ASN1EncodableVector_H