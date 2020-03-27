//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/ProtectedPart.java
//

#ifndef ProtectedPart_H
#define ProtectedPart_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmpPKIBody;
@class LibOrgBouncycastleAsn1CmpPKIHeader;

@interface LibOrgBouncycastleAsn1CmpProtectedPart : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpPKIHeader:(LibOrgBouncycastleAsn1CmpPKIHeader *)header
                                withLibOrgBouncycastleAsn1CmpPKIBody:(LibOrgBouncycastleAsn1CmpPKIBody *)body;

- (LibOrgBouncycastleAsn1CmpPKIBody *)getBody;

- (LibOrgBouncycastleAsn1CmpPKIHeader *)getHeader;

+ (LibOrgBouncycastleAsn1CmpProtectedPart *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpProtectedPart)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpProtectedPart *LibOrgBouncycastleAsn1CmpProtectedPart_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1CmpPKIHeader_withLibOrgBouncycastleAsn1CmpPKIBody_(LibOrgBouncycastleAsn1CmpProtectedPart *self, LibOrgBouncycastleAsn1CmpPKIHeader *header, LibOrgBouncycastleAsn1CmpPKIBody *body);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpProtectedPart *new_LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1CmpPKIHeader_withLibOrgBouncycastleAsn1CmpPKIBody_(LibOrgBouncycastleAsn1CmpPKIHeader *header, LibOrgBouncycastleAsn1CmpPKIBody *body) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpProtectedPart *create_LibOrgBouncycastleAsn1CmpProtectedPart_initWithLibOrgBouncycastleAsn1CmpPKIHeader_withLibOrgBouncycastleAsn1CmpPKIBody_(LibOrgBouncycastleAsn1CmpPKIHeader *header, LibOrgBouncycastleAsn1CmpPKIBody *body);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpProtectedPart)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ProtectedPart_H