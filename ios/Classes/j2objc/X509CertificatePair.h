//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509CertificatePair.java
//

#ifndef X509CertificatePair_H
#define X509CertificatePair_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecurityCertX509Certificate;
@class LibOrgBouncycastleAsn1X509CertificatePair;

@interface LibOrgBouncycastleX509X509CertificatePair : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509CertificatePair:(LibOrgBouncycastleAsn1X509CertificatePair *)pair;

- (instancetype __nonnull)initWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)forward
                              withJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)reverse;

- (jboolean)isEqual:(id)o;

- (IOSByteArray *)getEncoded;

- (JavaSecurityCertX509Certificate *)getForward;

- (JavaSecurityCertX509Certificate *)getReverse;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509X509CertificatePair)

FOUNDATION_EXPORT void LibOrgBouncycastleX509X509CertificatePair_initWithJavaSecurityCertX509Certificate_withJavaSecurityCertX509Certificate_(LibOrgBouncycastleX509X509CertificatePair *self, JavaSecurityCertX509Certificate *forward, JavaSecurityCertX509Certificate *reverse);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509CertificatePair *new_LibOrgBouncycastleX509X509CertificatePair_initWithJavaSecurityCertX509Certificate_withJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *forward, JavaSecurityCertX509Certificate *reverse) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509X509CertificatePair *create_LibOrgBouncycastleX509X509CertificatePair_initWithJavaSecurityCertX509Certificate_withJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *forward, JavaSecurityCertX509Certificate *reverse);

FOUNDATION_EXPORT void LibOrgBouncycastleX509X509CertificatePair_initWithLibOrgBouncycastleAsn1X509CertificatePair_(LibOrgBouncycastleX509X509CertificatePair *self, LibOrgBouncycastleAsn1X509CertificatePair *pair);

FOUNDATION_EXPORT LibOrgBouncycastleX509X509CertificatePair *new_LibOrgBouncycastleX509X509CertificatePair_initWithLibOrgBouncycastleAsn1X509CertificatePair_(LibOrgBouncycastleAsn1X509CertificatePair *pair) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509X509CertificatePair *create_LibOrgBouncycastleX509X509CertificatePair_initWithLibOrgBouncycastleAsn1X509CertificatePair_(LibOrgBouncycastleAsn1X509CertificatePair *pair);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509X509CertificatePair)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509CertificatePair_H
