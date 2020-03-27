//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/ErrorMsgContent.java
//

#ifndef ErrorMsgContent_H
#define ErrorMsgContent_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1CmpPKIFreeText;
@class LibOrgBouncycastleAsn1CmpPKIStatusInfo;

@interface LibOrgBouncycastleAsn1CmpErrorMsgContent : LibOrgBouncycastleAsn1ASN1Object

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo:(LibOrgBouncycastleAsn1CmpPKIStatusInfo *)pkiStatusInfo;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo:(LibOrgBouncycastleAsn1CmpPKIStatusInfo *)pkiStatusInfo
                                   withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)errorCode
                                withLibOrgBouncycastleAsn1CmpPKIFreeText:(LibOrgBouncycastleAsn1CmpPKIFreeText *)errorDetails;

- (LibOrgBouncycastleAsn1ASN1Integer *)getErrorCode;

- (LibOrgBouncycastleAsn1CmpPKIFreeText *)getErrorDetails;

+ (LibOrgBouncycastleAsn1CmpErrorMsgContent *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1CmpPKIStatusInfo *)getPKIStatusInfo;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpErrorMsgContent)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpErrorMsgContent *LibOrgBouncycastleAsn1CmpErrorMsgContent_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpErrorMsgContent_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_(LibOrgBouncycastleAsn1CmpErrorMsgContent *self, LibOrgBouncycastleAsn1CmpPKIStatusInfo *pkiStatusInfo);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpErrorMsgContent *new_LibOrgBouncycastleAsn1CmpErrorMsgContent_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *pkiStatusInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpErrorMsgContent *create_LibOrgBouncycastleAsn1CmpErrorMsgContent_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *pkiStatusInfo);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpErrorMsgContent_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1CmpErrorMsgContent *self, LibOrgBouncycastleAsn1CmpPKIStatusInfo *pkiStatusInfo, LibOrgBouncycastleAsn1ASN1Integer *errorCode, LibOrgBouncycastleAsn1CmpPKIFreeText *errorDetails);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpErrorMsgContent *new_LibOrgBouncycastleAsn1CmpErrorMsgContent_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *pkiStatusInfo, LibOrgBouncycastleAsn1ASN1Integer *errorCode, LibOrgBouncycastleAsn1CmpPKIFreeText *errorDetails) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpErrorMsgContent *create_LibOrgBouncycastleAsn1CmpErrorMsgContent_initWithLibOrgBouncycastleAsn1CmpPKIStatusInfo_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *pkiStatusInfo, LibOrgBouncycastleAsn1ASN1Integer *errorCode, LibOrgBouncycastleAsn1CmpPKIFreeText *errorDetails);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpErrorMsgContent)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ErrorMsgContent_H