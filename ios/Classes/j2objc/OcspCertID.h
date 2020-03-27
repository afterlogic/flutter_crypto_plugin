//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ocsp/OcspCertID.java
//

#ifndef OcspCertID_H
#define OcspCertID_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1OctetString;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;

@interface LibOrgBouncycastleAsn1OcspOcspCertID : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm_;
  LibOrgBouncycastleAsn1ASN1OctetString *issuerNameHash_;
  LibOrgBouncycastleAsn1ASN1OctetString *issuerKeyHash_;
  LibOrgBouncycastleAsn1ASN1Integer *serialNumber_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)hashAlgorithm
                                      withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)issuerNameHash
                                      withLibOrgBouncycastleAsn1ASN1OctetString:(LibOrgBouncycastleAsn1ASN1OctetString *)issuerKeyHash
                                          withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)serialNumber;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getHashAlgorithm;

+ (LibOrgBouncycastleAsn1OcspOcspCertID *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                    withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1OcspOcspCertID *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getIssuerKeyHash;

- (LibOrgBouncycastleAsn1ASN1OctetString *)getIssuerNameHash;

- (LibOrgBouncycastleAsn1ASN1Integer *)getSerialNumber;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1OcspOcspCertID)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspOcspCertID, hashAlgorithm_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspOcspCertID, issuerNameHash_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspOcspCertID, issuerKeyHash_, LibOrgBouncycastleAsn1ASN1OctetString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1OcspOcspCertID, serialNumber_, LibOrgBouncycastleAsn1ASN1Integer *)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1OcspOcspCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1OcspOcspCertID *self, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *issuerNameHash, LibOrgBouncycastleAsn1ASN1OctetString *issuerKeyHash, LibOrgBouncycastleAsn1ASN1Integer *serialNumber);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOcspCertID *new_LibOrgBouncycastleAsn1OcspOcspCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *issuerNameHash, LibOrgBouncycastleAsn1ASN1OctetString *issuerKeyHash, LibOrgBouncycastleAsn1ASN1Integer *serialNumber) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOcspCertID *create_LibOrgBouncycastleAsn1OcspOcspCertID_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1OctetString_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm, LibOrgBouncycastleAsn1ASN1OctetString *issuerNameHash, LibOrgBouncycastleAsn1ASN1OctetString *issuerKeyHash, LibOrgBouncycastleAsn1ASN1Integer *serialNumber);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOcspCertID *LibOrgBouncycastleAsn1OcspOcspCertID_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1OcspOcspCertID *LibOrgBouncycastleAsn1OcspOcspCertID_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1OcspOcspCertID)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OcspCertID_H
