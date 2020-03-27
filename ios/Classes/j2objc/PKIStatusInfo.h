//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cmp/PKIStatusInfo.java
//

#ifndef PKIStatusInfo_H
#define PKIStatusInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1CmpPKIFailureInfo;
@class LibOrgBouncycastleAsn1CmpPKIFreeText;
@class LibOrgBouncycastleAsn1CmpPKIStatus;
@class LibOrgBouncycastleAsn1DERBitString;

@interface LibOrgBouncycastleAsn1CmpPKIStatusInfo : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *status_;
  LibOrgBouncycastleAsn1CmpPKIFreeText *statusString_;
  LibOrgBouncycastleAsn1DERBitString *failInfo_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpPKIStatus:(LibOrgBouncycastleAsn1CmpPKIStatus *)status;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpPKIStatus:(LibOrgBouncycastleAsn1CmpPKIStatus *)status
                            withLibOrgBouncycastleAsn1CmpPKIFreeText:(LibOrgBouncycastleAsn1CmpPKIFreeText *)statusString;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1CmpPKIStatus:(LibOrgBouncycastleAsn1CmpPKIStatus *)status
                            withLibOrgBouncycastleAsn1CmpPKIFreeText:(LibOrgBouncycastleAsn1CmpPKIFreeText *)statusString
                         withLibOrgBouncycastleAsn1CmpPKIFailureInfo:(LibOrgBouncycastleAsn1CmpPKIFailureInfo *)failInfo;

- (LibOrgBouncycastleAsn1DERBitString *)getFailInfo;

+ (LibOrgBouncycastleAsn1CmpPKIStatusInfo *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1CmpPKIStatusInfo *)getInstanceWithId:(id)obj;

- (JavaMathBigInteger *)getStatus;

- (LibOrgBouncycastleAsn1CmpPKIFreeText *)getStatusString;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1CmpPKIStatusInfo)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIStatusInfo, status_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIStatusInfo, statusString_, LibOrgBouncycastleAsn1CmpPKIFreeText *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CmpPKIStatusInfo, failInfo_, LibOrgBouncycastleAsn1DERBitString *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIStatusInfo *LibOrgBouncycastleAsn1CmpPKIStatusInfo_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIStatusInfo *LibOrgBouncycastleAsn1CmpPKIStatusInfo_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *self, LibOrgBouncycastleAsn1CmpPKIStatus *status);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIStatusInfo *new_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_(LibOrgBouncycastleAsn1CmpPKIStatus *status) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIStatusInfo *create_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_(LibOrgBouncycastleAsn1CmpPKIStatus *status);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *self, LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIStatusInfo *new_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIStatusInfo *create_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_(LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_withLibOrgBouncycastleAsn1CmpPKIFailureInfo_(LibOrgBouncycastleAsn1CmpPKIStatusInfo *self, LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString, LibOrgBouncycastleAsn1CmpPKIFailureInfo *failInfo);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIStatusInfo *new_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_withLibOrgBouncycastleAsn1CmpPKIFailureInfo_(LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString, LibOrgBouncycastleAsn1CmpPKIFailureInfo *failInfo) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1CmpPKIStatusInfo *create_LibOrgBouncycastleAsn1CmpPKIStatusInfo_initWithLibOrgBouncycastleAsn1CmpPKIStatus_withLibOrgBouncycastleAsn1CmpPKIFreeText_withLibOrgBouncycastleAsn1CmpPKIFailureInfo_(LibOrgBouncycastleAsn1CmpPKIStatus *status, LibOrgBouncycastleAsn1CmpPKIFreeText *statusString, LibOrgBouncycastleAsn1CmpPKIFailureInfo *failInfo);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1CmpPKIStatusInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKIStatusInfo_H
