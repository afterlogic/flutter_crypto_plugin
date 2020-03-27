//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x509/V2TBSCertListGenerator.java
//

#ifndef V2TBSCertListGenerator_H
#define V2TBSCertListGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1ASN1GeneralizedTime;
@class LibOrgBouncycastleAsn1ASN1Integer;
@class LibOrgBouncycastleAsn1ASN1Sequence;
@class LibOrgBouncycastleAsn1ASN1UTCTime;
@class LibOrgBouncycastleAsn1X500X500Name;
@class LibOrgBouncycastleAsn1X509AlgorithmIdentifier;
@class LibOrgBouncycastleAsn1X509Asn1X509Time;
@class LibOrgBouncycastleAsn1X509Extensions;
@class LibOrgBouncycastleAsn1X509TBSCertList;
@class LibOrgBouncycastleAsn1X509X509Extensions;
@class LibOrgBouncycastleAsn1X509X509Name;

@interface LibOrgBouncycastleAsn1X509V2TBSCertListGenerator : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

- (void)addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)userCertificate
                   withLibOrgBouncycastleAsn1ASN1UTCTime:(LibOrgBouncycastleAsn1ASN1UTCTime *)revocationDate
                                                 withInt:(jint)reason;

- (void)addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)userCertificate
              withLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)revocationDate
                withLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions;

- (void)addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)userCertificate
              withLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)revocationDate
                                                 withInt:(jint)reason;

- (void)addCRLEntryWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)userCertificate
              withLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)revocationDate
                                                 withInt:(jint)reason
           withLibOrgBouncycastleAsn1ASN1GeneralizedTime:(LibOrgBouncycastleAsn1ASN1GeneralizedTime *)invalidityDate;

- (void)addCRLEntryWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)crlEntry;

- (LibOrgBouncycastleAsn1X509TBSCertList *)generateTBSCertList;

- (void)setExtensionsWithLibOrgBouncycastleAsn1X509Extensions:(LibOrgBouncycastleAsn1X509Extensions *)extensions;

- (void)setExtensionsWithLibOrgBouncycastleAsn1X509X509Extensions:(LibOrgBouncycastleAsn1X509X509Extensions *)extensions;

- (void)setIssuerWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)issuer;

- (void)setIssuerWithLibOrgBouncycastleAsn1X509X509Name:(LibOrgBouncycastleAsn1X509X509Name *)issuer;

- (void)setNextUpdateWithLibOrgBouncycastleAsn1ASN1UTCTime:(LibOrgBouncycastleAsn1ASN1UTCTime *)nextUpdate;

- (void)setNextUpdateWithLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)nextUpdate;

- (void)setSignatureWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier:(LibOrgBouncycastleAsn1X509AlgorithmIdentifier *)signature;

- (void)setThisUpdateWithLibOrgBouncycastleAsn1ASN1UTCTime:(LibOrgBouncycastleAsn1ASN1UTCTime *)thisUpdate;

- (void)setThisUpdateWithLibOrgBouncycastleAsn1X509Asn1X509Time:(LibOrgBouncycastleAsn1X509Asn1X509Time *)thisUpdate;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_init(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator *self);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509V2TBSCertListGenerator *new_LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X509V2TBSCertListGenerator *create_LibOrgBouncycastleAsn1X509V2TBSCertListGenerator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1X509V2TBSCertListGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // V2TBSCertListGenerator_H
