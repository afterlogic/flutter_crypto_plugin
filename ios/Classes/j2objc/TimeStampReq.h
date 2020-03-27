//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/TimeStampReq.java
//

#ifndef TimeStampReq_H
#define TimeStampReq_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Boolean;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1TspMessageImprint;
@class LibOrgBouncycastleAsn1X509Extensions;

@interface LibOrgBouncycastleAsn1TspTimeStampReq : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *version__;
  LibOrgBouncycastleAsn1TspMessageImprint *messageImprint_;
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicy_;
  LibOrgBouncycastleAsn1ASN1Integer *nonce_;
  LibOrgBouncycastleAsn1ASN1Boolean *certReq_;
  LibOrgBouncycastleAsn1X509Extensions *extensions_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1TspMessageImprint:(LibOrgBouncycastleAsn1TspMessageImprint *)messageImprint
                           withLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)tsaPolicy
                                    withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)nonce
                                    withLibOrgBouncycastleAsn1ASN1Boolean:(LibOrgBouncycastleAsn1ASN1Boolean *)certReq
                                 withLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions;

- (LibOrgBouncycastleAsn1ASN1Boolean *)getCertReq;

- (LibOrgBouncycastleAsn1X509Extensions *)getExtensions;

+ (LibOrgBouncycastleAsn1TspTimeStampReq *)getInstanceWithId:(id)o;

- (LibOrgBouncycastleAsn1TspMessageImprint *)getMessageImprint;

- (LibOrgBouncycastleAsn1ASN1Integer *)getNonce;

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getReqPolicy;

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1TspTimeStampReq)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTimeStampReq, version__, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTimeStampReq, messageImprint_, LibOrgBouncycastleAsn1TspMessageImprint *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTimeStampReq, tsaPolicy_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTimeStampReq, nonce_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTimeStampReq, certReq_, LibOrgBouncycastleAsn1ASN1Boolean *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1TspTimeStampReq, extensions_, LibOrgBouncycastleAsn1X509Extensions *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspTimeStampReq *LibOrgBouncycastleAsn1TspTimeStampReq_getInstanceWithId_(id o);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1TspTimeStampReq *self, LibOrgBouncycastleAsn1TspMessageImprint *messageImprint, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicy, LibOrgBouncycastleAsn1ASN1Integer *nonce, LibOrgBouncycastleAsn1ASN1Boolean *certReq, LibOrgBouncycastleAsn1X509Extensions *extensions);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspTimeStampReq *new_LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1TspMessageImprint *messageImprint, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicy, LibOrgBouncycastleAsn1ASN1Integer *nonce, LibOrgBouncycastleAsn1ASN1Boolean *certReq, LibOrgBouncycastleAsn1X509Extensions *extensions) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1TspTimeStampReq *create_LibOrgBouncycastleAsn1TspTimeStampReq_initWithLibOrgBouncycastleAsn1TspMessageImprint_withLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Boolean_withLibOrgBouncycastleAsn1X509Extensions_(LibOrgBouncycastleAsn1TspMessageImprint *messageImprint, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *tsaPolicy, LibOrgBouncycastleAsn1ASN1Integer *nonce, LibOrgBouncycastleAsn1ASN1Boolean *certReq, LibOrgBouncycastleAsn1X509Extensions *extensions);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1TspTimeStampReq)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TimeStampReq_H