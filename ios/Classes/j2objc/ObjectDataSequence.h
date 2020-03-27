//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/bc/ObjectDataSequence.java
//

#ifndef ObjectDataSequence_H
#define ObjectDataSequence_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "Iterable.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@protocol JavaUtilFunctionConsumer;
@protocol JavaUtilIterator;
@protocol JavaUtilSpliterator;

@interface LibOrgBouncycastleAsn1BcObjectDataSequence : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleUtilIterable >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1BcObjectDataArray:(IOSObjectArray *)dataSequence;

+ (LibOrgBouncycastleAsn1BcObjectDataSequence *)getInstanceWithId:(id)obj;

- (id<JavaUtilIterator>)iterator;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

#pragma mark Package-Private

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1BcObjectDataSequence)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1BcObjectDataSequence_initWithLibOrgBouncycastleAsn1BcObjectDataArray_(LibOrgBouncycastleAsn1BcObjectDataSequence *self, IOSObjectArray *dataSequence);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcObjectDataSequence *new_LibOrgBouncycastleAsn1BcObjectDataSequence_initWithLibOrgBouncycastleAsn1BcObjectDataArray_(IOSObjectArray *dataSequence) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcObjectDataSequence *create_LibOrgBouncycastleAsn1BcObjectDataSequence_initWithLibOrgBouncycastleAsn1BcObjectDataArray_(IOSObjectArray *dataSequence);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1BcObjectDataSequence *LibOrgBouncycastleAsn1BcObjectDataSequence_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1BcObjectDataSequence)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ObjectDataSequence_H