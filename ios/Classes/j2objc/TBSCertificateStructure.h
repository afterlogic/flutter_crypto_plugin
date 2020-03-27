//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/TBSCertificateStructure.java
//

#ifndef TBSCertificateStructure_H
#define TBSCertificateStructure_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"
#include "PKCSObjectIdentifiers.h"
#include "X509ObjectIdentifiers.h"

@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1DERBitString;
@class LibOrgBouncycastleAsn1X500X500Name;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@class LibOrgBouncycastleAsn1X509Asn1X509Time;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@class LibOrgBouncycastleAsn1X509X509Extensions;

@interface LibOrgBouncycastleAsn1X509TBSCertificateStructure : LibOrgBouncycastleAsn1ASN1Object < LibOrgBouncycastleAsn1X509X509ObjectIdentifiers, LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers > {
 @public
  LibOrgBouncycastleAsn1ASN1Sequence *seq_;
  LibOrgBouncycastleAsn1ASN1Integer *version__;
  LibOrgBouncycastleAsn1ASN1Integer *serialNumber_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signature_;
  LibOrgBouncycastleAsn1X500X500Name *issuer_;
  LibOrgBouncycastleAsn1X509Asn1X509Time *startDate_;
  LibOrgBouncycastleAsn1X509Asn1X509Time *endDate_;
  LibOrgBouncycastleAsn1X500X500Name *subject_;
  LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *subjectPublicKeyInfo_;
  LibOrgBouncycastleAsn1DERBitString *issuerUniqueId_;
  LibOrgBouncycastleAsn1DERBitString *subjectUniqueId_;
  LibOrgBouncycastleAsn1X509X509Extensions *extensions_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

- (LibOrgBouncycastleAsn1X509Asn1X509Time *)getEndDate;

- (LibOrgBouncycastleAsn1X509X509Extensions *)getExtensions;

+ (LibOrgBouncycastleAsn1X509TBSCertificateStructure *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                                 withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1X509TBSCertificateStructure *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1X500X500Name *)getIssuer;

- (LibOrgBouncycastleAsn1DERBitString *)getIssuerUniqueId;

- (LibOrgBouncycastleAsn1ASN1Integer *)getSerialNumber;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getSignature;

- (LibOrgBouncycastleAsn1X509Asn1X509Time *)getStartDate;

- (LibOrgBouncycastleAsn1X500X500Name *)getSubject;

- (LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)getSubjectPublicKeyInfo;

- (LibOrgBouncycastleAsn1DERBitString *)getSubjectUniqueId;

- (jint)getVersion;

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersionNumber;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509TBSCertificateStructure)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, seq_, LibOrgBouncycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, version__, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, serialNumber_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, signature_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, issuer_, LibOrgBouncycastleAsn1X500X500Name *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, startDate_, LibOrgBouncycastleAsn1X509Asn1X509Time *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, endDate_, LibOrgBouncycastleAsn1X509Asn1X509Time *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, subject_, LibOrgBouncycastleAsn1X500X500Name *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, subjectPublicKeyInfo_, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, issuerUniqueId_, LibOrgBouncycastleAsn1DERBitString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, subjectUniqueId_, LibOrgBouncycastleAsn1DERBitString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509TBSCertificateStructure, extensions_, LibOrgBouncycastleAsn1X509X509Extensions *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509TBSCertificateStructure *LibOrgBouncycastleAsn1X509TBSCertificateStructure_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509TBSCertificateStructure *LibOrgBouncycastleAsn1X509TBSCertificateStructure_getInstanceWithId_(id obj);

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509TBSCertificateStructure_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X509TBSCertificateStructure *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509TBSCertificateStructure *new_LibOrgBouncycastleAsn1X509TBSCertificateStructure_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509TBSCertificateStructure *create_LibOrgBouncycastleAsn1X509TBSCertificateStructure_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509TBSCertificateStructure)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TBSCertificateStructure_H
