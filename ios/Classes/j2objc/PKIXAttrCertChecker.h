//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/PKIXAttrCertChecker.java
//

#ifndef PKIXAttrCertChecker_H
#define PKIXAttrCertChecker_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecurityCertCertPath;
@protocol JavaUtilCollection;
@protocol JavaUtilSet;
@protocol LibOrgBouncycastleX509X509AttributeCertificate;

@interface LibOrgBouncycastleX509PKIXAttrCertChecker : NSObject < NSCopying >

#pragma mark Public

- (instancetype __nonnull)init;

- (void)checkWithLibOrgBouncycastleX509X509AttributeCertificate:(id<LibOrgBouncycastleX509X509AttributeCertificate>)attrCert
                                   withJavaSecurityCertCertPath:(JavaSecurityCertCertPath *)certPath
                                   withJavaSecurityCertCertPath:(JavaSecurityCertCertPath *)holderCertPath
                                         withJavaUtilCollection:(id<JavaUtilCollection>)unresolvedCritExts;

- (id)java_clone;

- (id<JavaUtilSet>)getSupportedExtensions;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509PKIXAttrCertChecker)

FOUNDATION_EXPORT void LibOrgBouncycastleX509PKIXAttrCertChecker_init(LibOrgBouncycastleX509PKIXAttrCertChecker *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509PKIXAttrCertChecker)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKIXAttrCertChecker_H
