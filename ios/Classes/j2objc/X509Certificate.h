//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/X509Certificate.java
//

#ifndef X509Certificate_H
#define X509Certificate_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ASN1Object.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1TaggedObject;
@class LibOrgBouncycastleAsn1DERBitString;
@class LibOrgBouncycastleAsn1X500X500Name;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@class LibOrgBouncycastleAsn1X509Asn1X509Time;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@class LibOrgBouncycastleAsn1X509TBSCertificate;

@interface LibOrgBouncycastleAsn1X509X509Certificate : LibOrgBouncycastleAsn1ASN1Object {
 @public
  LibOrgBouncycastleAsn1ASN1Sequence *seq_;
  LibOrgBouncycastleAsn1X509TBSCertificate *tbsCert_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *sigAlgId_;
  LibOrgBouncycastleAsn1DERBitString *sig_;
}

#pragma mark Public

- (LibOrgBouncycastleAsn1X509Asn1X509Time *)getEndDate;

+ (LibOrgBouncycastleAsn1X509X509Certificate *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                         withBoolean:(jboolean)explicit_;

+ (LibOrgBouncycastleAsn1X509X509Certificate *)getInstanceWithId:(id)obj;

- (LibOrgBouncycastleAsn1X500X500Name *)getIssuer;

- (LibOrgBouncycastleAsn1ASN1Integer *)getSerialNumber;

- (LibOrgBouncycastleAsn1DERBitString *)getSignature;

- (LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)getSignatureAlgorithm;

- (LibOrgBouncycastleAsn1X509Asn1X509Time *)getStartDate;

- (LibOrgBouncycastleAsn1X500X500Name *)getSubject;

- (LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)getSubjectPublicKeyInfo;

- (LibOrgBouncycastleAsn1X509TBSCertificate *)getTBSCertificate;

- (LibOrgBouncycastleAsn1ASN1Integer *)getVersion;

- (jint)getVersionNumber;

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleAsn1X509X509Certificate)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509X509Certificate, seq_, LibOrgBouncycastleAsn1ASN1Sequence *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509X509Certificate, tbsCert_, LibOrgBouncycastleAsn1X509TBSCertificate *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509X509Certificate, sigAlgId_, LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X509X509Certificate, sig_, LibOrgBouncycastleAsn1DERBitString *)

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Certificate *LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509X509Certificate *LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithId_(id obj);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509X509Certificate)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509Certificate_H
