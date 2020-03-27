//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509CRLStoreSelector.java
//

#ifndef X509CRLStoreSelector_H
#define X509CRLStoreSelector_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Selector.h"
#include "java/security/cert/X509CRLSelector.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaSecurityCertCRL;
@protocol LibOrgBouncycastleX509X509AttributeCertificate;

@interface LibOrgBouncycastleX509X509CRLStoreSelector : JavaSecurityCertX509CRLSelector < LibOrgBouncycastleUtilSelector >

#pragma mark Public

- (instancetype __nonnull)init;

- (id)java_clone;

- (id<LibOrgBouncycastleX509X509AttributeCertificate>)getAttrCertificateChecking;

+ (LibOrgBouncycastleX509X509CRLStoreSelector *)getInstanceWithJavaSecurityCertX509CRLSelector:(JavaSecurityCertX509CRLSelector *)selector;

- (IOSByteArray *)getIssuingDistributionPoint;

- (JavaMathBigInteger *)getMaxBaseCRLNumber;

- (jboolean)isCompleteCRLEnabled;

- (jboolean)isDeltaCRLIndicatorEnabled;

- (jboolean)isIssuingDistributionPointEnabled;

- (jboolean)matchWithJavaSecurityCertCRL:(JavaSecurityCertCRL *)crl;

- (jboolean)matchWithId:(id)obj;

- (void)setAttrCertificateCheckingWithLibOrgBouncycastleX509X509AttributeCertificate:(id<LibOrgBouncycastleX509X509AttributeCertificate>)attrCert;

- (void)setCompleteCRLEnabledWithBoolean:(jboolean)completeCRLEnabled;

- (void)setDeltaCRLIndicatorEnabledWithBoolean:(jboolean)deltaCRLIndicator;

- (void)setIssuingDistributionPointWithByteArray:(IOSByteArray *)issuingDistributionPoint;

- (void)setIssuingDistributionPointEnabledWithBoolean:(jboolean)issuingDistributionPointEnabled;

- (void)setMaxBaseCRLNumberWithJavaMathBigInteger:(JavaMathBigInteger *)maxBaseCRLNumber;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509X509CRLStoreSelector)

FOUNDATION_EXPORT void LibOrgBouncycastleX509X509CRLStoreSelector_init(LibOrgBouncycastleX509X509CRLStoreSelector *self);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509CRLStoreSelector *new_LibOrgBouncycastleX509X509CRLStoreSelector_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509X509CRLStoreSelector *create_LibOrgBouncycastleX509X509CRLStoreSelector_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509CRLStoreSelector *LibOrgBouncycastleX509X509CRLStoreSelector_getInstanceWithJavaSecurityCertX509CRLSelector_(JavaSecurityCertX509CRLSelector *selector);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509X509CRLStoreSelector)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509CRLStoreSelector_H
