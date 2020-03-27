//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/x509/CertificateFactory.java
//

#ifndef CertificateFactory_H
#define CertificateFactory_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/cert/CertificateFactorySpi.h"

@class JavaIoInputStream;
@class JavaSecurityCertCRL;
@class JavaSecurityCertCertPath;
@class JavaSecurityCertCertificate;
@class LibOrgBouncycastleAsn1X509CertificateList;
@protocol JavaUtilCollection;
@protocol JavaUtilIterator;
@protocol JavaUtilList;

@interface LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory : JavaSecurityCertCertificateFactorySpi

#pragma mark Public

- (instancetype __nonnull)init;

- (JavaSecurityCertCertificate *)engineGenerateCertificateWithJavaIoInputStream:(JavaIoInputStream *)inArg;

- (id<JavaUtilCollection>)engineGenerateCertificatesWithJavaIoInputStream:(JavaIoInputStream *)inStream;

- (JavaSecurityCertCertPath *)engineGenerateCertPathWithJavaIoInputStream:(JavaIoInputStream *)inStream;

- (JavaSecurityCertCertPath *)engineGenerateCertPathWithJavaIoInputStream:(JavaIoInputStream *)inStream
                                                             withNSString:(NSString *)encoding;

- (JavaSecurityCertCertPath *)engineGenerateCertPathWithJavaUtilList:(id<JavaUtilList>)certificates;

- (JavaSecurityCertCRL *)engineGenerateCRLWithJavaIoInputStream:(JavaIoInputStream *)inArg;

- (id<JavaUtilCollection>)engineGenerateCRLsWithJavaIoInputStream:(JavaIoInputStream *)inStream;

- (id<JavaUtilIterator>)engineGetCertPathEncodings;

#pragma mark Protected

- (JavaSecurityCertCRL *)createCRLWithLibOrgBouncycastleAsn1X509CertificateList:(LibOrgBouncycastleAsn1X509CertificateList *)c;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_init(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *new_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory *create_LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricX509CertificateFactory)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertificateFactory_H