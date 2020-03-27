//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/V3TBSCertificateGenerator.java
//

#ifndef V3TBSCertificateGenerator_H
#define V3TBSCertificateGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1UTCTime;
@class LibOrgBouncycastleAsn1DERBitString;
@class LibOrgBouncycastleAsn1DERTaggedObject;
@class LibOrgBouncycastleAsn1X500X500Name;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@class LibOrgBouncycastleAsn1X509Asn1X509Time;
@class LibOrgBouncycastleAsn1X509Extensions;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@class LibOrgBouncycastleAsn1X509TBSCertificate;
@class LibOrgBouncycastleAsn1X509X509Extensions;
@class LibOrgBouncycastleAsn1X509X509Name;

@interface LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator : NSObject {
 @public
  LibOrgBouncycastleAsn1DERTaggedObject *version__;
  LibOrgBouncycastleAsn1ASN1Integer *serialNumber_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *signature_;
  LibOrgBouncycastleAsn1X500X500Name *issuer_;
  LibOrgBouncycastleAsn1X509Asn1X509Time *startDate_;
  LibOrgBouncycastleAsn1X509Asn1X509Time *endDate_;
  LibOrgBouncycastleAsn1X500X500Name *subject_;
  LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *subjectPublicKeyInfo_;
  LibOrgBouncycastleAsn1X509Extensions *extensions_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (LibOrgBouncycastleAsn1X509TBSCertificate *)generateTBSCertificate;

- (void)setEndDateWithLibOrgBouncycastleAsn1ASN1UTCTime:(LibOrgBouncycastleAsn1ASN1UTCTime *)endDate;

- (void)setEndDateWithLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)endDate;

- (void)setExtensionsWithLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions;

- (void)setExtensionsWithLibOrgBouncycastleAsn1X509X509Extensions:(LibOrgBouncycastleAsn1X509X509Extensions *)extensions;

- (void)setIssuerWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)issuer;

- (void)setIssuerWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)issuer;

- (void)setIssuerUniqueIDWithLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)uniqueID;

- (void)setSerialNumberWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)serialNumber;

- (void)setSignatureWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)signature;

- (void)setStartDateWithLibOrgBouncycastleAsn1ASN1UTCTime:(LibOrgBouncycastleAsn1ASN1UTCTime *)startDate;

- (void)setStartDateWithLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)startDate;

- (void)setSubjectWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)subject;

- (void)setSubjectWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)subject;

- (void)setSubjectPublicKeyInfoWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)pubKeyInfo;

- (void)setSubjectUniqueIDWithLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)uniqueID;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, version__, LibOrgBouncycastleAsn1DERTaggedObject *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, serialNumber_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, signature_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, issuer_, LibOrgBouncycastleAsn1X500X500Name *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, startDate_, LibOrgBouncycastleAsn1X509Asn1X509Time *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, endDate_, LibOrgBouncycastleAsn1X509Asn1X509Time *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, subject_, LibOrgBouncycastleAsn1X500X500Name *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, subjectPublicKeyInfo_, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator, extensions_, LibOrgBouncycastleAsn1X509Extensions *)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator_init(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator *new_LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator *create_LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509V3TBSCertificateGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // V3TBSCertificateGenerator_H
