//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/OCSPResponse.java
//

#ifndef OCSPResponse_H
#define OCSPResponse_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1OcspOCSPResponseStatus;
@class LibOrgBouncycastleAsn1OcspResponseBytes;

@interface LibOrgBouncycastleAsn1OcspOCSPResponse : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1OcspOCSPResponseStatus *responseStatus_;
  LibOrgBouncycastleAsn1OcspResponseBytes *responseBytes_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1OcspOCSPResponseStatus:(LibOrgBouncycastleAsn1OcspOCSPResponseStatus *)responseStatus
                                   withLibOrgBouncycastleAsn1OcspResponseBytes:(LibOrgBouncycastleAsn1OcspResponseBytes *)responseBytes;

+ (LibOrgBouncycastleAsn1OcspOCSPResponse *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                      withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1OcspOCSPResponse *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1OcspResponseBytes *)getResponseBytes;

- (LibOrgBouncycastleAsn1OcspOCSPResponseStatus *)getResponseStatus;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1OcspOCSPResponse)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspOCSPResponse, responseStatus_, LibOrgBouncycastleAsn1OcspOCSPResponseStatus *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspOCSPResponse, responseBytes_, LibOrgBouncycastleAsn1OcspResponseBytes *)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1OcspOCSPResponse_initWithLibOrgBouncycastleAsn1OcspOCSPResponseStatus_withLibOrgBouncycastleAsn1OcspResponseBytes_(LibOrgBouncycastleAsn1OcspOCSPResponse *self, LibOrgBouncycastleAsn1OcspOCSPResponseStatus *responseStatus, LibOrgBouncycastleAsn1OcspResponseBytes *responseBytes);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOCSPResponse *new_LibOrgBouncycastleAsn1OcspOCSPResponse_initWithLibOrgBouncycastleAsn1OcspOCSPResponseStatus_withLibOrgBouncycastleAsn1OcspResponseBytes_(LibOrgBouncycastleAsn1OcspOCSPResponseStatus *responseStatus, LibOrgBouncycastleAsn1OcspResponseBytes *responseBytes) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOCSPResponse *create_LibOrgBouncycastleAsn1OcspOCSPResponse_initWithLibOrgBouncycastleAsn1OcspOCSPResponseStatus_withLibOrgBouncycastleAsn1OcspResponseBytes_(LibOrgBouncycastleAsn1OcspOCSPResponseStatus *responseStatus, LibOrgBouncycastleAsn1OcspResponseBytes *responseBytes);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOCSPResponse *LibOrgBouncycastleAsn1OcspOCSPResponse_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOCSPResponse *LibOrgBouncycastleAsn1OcspOCSPResponse_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1OcspOCSPResponse)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OCSPResponse_H
