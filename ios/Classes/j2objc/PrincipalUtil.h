//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/PrincipalUtil.java
//

#ifndef PrincipalUtil_H
#define PrincipalUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecurityCertX509CRL;
@class JavaSecurityCertX509Certificate;
@class LibOrgBouncycastleJceX509Principal;

@interface LibOrgBouncycastleJcePrincipalUtil : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleJceX509Principal *)getIssuerX509PrincipalWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert;

+ (LibOrgBouncycastleJceX509Principal *)getIssuerX509PrincipalWithJavaSecurityCertX509CRL:(JavaSecurityCertX509CRL *)crl;

+ (LibOrgBouncycastleJceX509Principal *)getSubjectX509PrincipalWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcePrincipalUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleJcePrincipalUtil_init(LibOrgBouncycastleJcePrincipalUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcePrincipalUtil *new_LibOrgBouncycastleJcePrincipalUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcePrincipalUtil *create_LibOrgBouncycastleJcePrincipalUtil_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *LibOrgBouncycastleJcePrincipalUtil_getIssuerX509PrincipalWithJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *cert);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *LibOrgBouncycastleJcePrincipalUtil_getSubjectX509PrincipalWithJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *cert);

FOUNDATION_EXPORT LibOrgBouncycastleJceX509Principal *LibOrgBouncycastleJcePrincipalUtil_getIssuerX509PrincipalWithJavaSecurityCertX509CRL_(JavaSecurityCertX509CRL *crl);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcePrincipalUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PrincipalUtil_H
