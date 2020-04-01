//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/Pfx.java
//

#ifndef Pfx_H
#define Pfx_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"
#include "PKCSObjectIdentifiers.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1PkcsContentInfo;
@class LibOrgBouncycastleAsn1PkcsMacData;

@interface LibOrgBouncycastleAsn1PkcsPfx : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1PkcsContentInfo:(LibOrgBouncycastleAsn1PkcsContentInfo *)contentInfo
                                  withLibOrgBouncycastleAsn1PkcsMacData:(LibOrgBouncycastleAsn1PkcsMacData *)macData;

- (LibOrgBouncycastleAsn1PkcsContentInfo *)getAuthSafe;

+ (LibOrgBouncycastleAsn1PkcsPfx *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1PkcsMacData *)getMacData;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1PkcsPfx)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsPfx *LibOrgBouncycastleAsn1PkcsPfx_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1PkcsPfx_initWithLibOrgBouncycastleAsn1PkcsContentInfo_withLibOrgBouncycastleAsn1PkcsMacData_(LibOrgBouncycastleAsn1PkcsPfx *self, LibOrgBouncycastleAsn1PkcsContentInfo *contentInfo, LibOrgBouncycastleAsn1PkcsMacData *macData);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsPfx *new_LibOrgBouncycastleAsn1PkcsPfx_initWithLibOrgBouncycastleAsn1PkcsContentInfo_withLibOrgBouncycastleAsn1PkcsMacData_(LibOrgBouncycastleAsn1PkcsContentInfo *contentInfo, LibOrgBouncycastleAsn1PkcsMacData *macData) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1PkcsPfx *create_LibOrgBouncycastleAsn1PkcsPfx_initWithLibOrgBouncycastleAsn1PkcsContentInfo_withLibOrgBouncycastleAsn1PkcsMacData_(LibOrgBouncycastleAsn1PkcsContentInfo *contentInfo, LibOrgBouncycastleAsn1PkcsMacData *macData);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1PkcsPfx)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Pfx_H