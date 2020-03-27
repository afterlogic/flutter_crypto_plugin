//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/Targets.java
//

#ifndef Targets_H
#define Targets_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class IOSObjectArray;
@class LibOrgBouncycastleAsn1ASN1Primitive;

@interface LibOrgBouncycastleAsn1X509Targets : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509TargetArray:(IOSObjectArray *)targets;

+ (LibOrgBouncycastleAsn1X509Targets *)getInstanceWithId:(id)obj;

- (IOSObjectArray *)getTargets;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509Targets)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509Targets *LibOrgBouncycastleAsn1X509Targets_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1X509TargetArray_(LibOrgBouncycastleAsn1X509Targets *self, IOSObjectArray *targets);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509Targets *new_LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1X509TargetArray_(IOSObjectArray *targets) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509Targets *create_LibOrgBouncycastleAsn1X509Targets_initWithLibOrgBouncycastleAsn1X509TargetArray_(IOSObjectArray *targets);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509Targets)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Targets_H
