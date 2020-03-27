//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/extension/X509ExtensionUtil.java
//

#ifndef X509ExtensionUtil_H
#define X509ExtensionUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaSecurityCertX509Certificate;
@class LibOrgBouncycastleAsn1ASN1Primitive;
@protocol JavaUtilCollection;

@interface LibOrgBouncycastleX509ExtensionX509ExtensionUtil : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleAsn1ASN1Primitive *)fromExtensionValueWithByteArray:(IOSByteArray *)encodedValue;

+ (id<JavaUtilCollection>)getIssuerAlternativeNamesWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert;

+ (id<JavaUtilCollection>)getSubjectAlternativeNamesWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)cert;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleX509ExtensionX509ExtensionUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleX509ExtensionX509ExtensionUtil_init(LibOrgBouncycastleX509ExtensionX509ExtensionUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleX509ExtensionX509ExtensionUtil *new_LibOrgBouncycastleX509ExtensionX509ExtensionUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleX509ExtensionX509ExtensionUtil *create_LibOrgBouncycastleX509ExtensionX509ExtensionUtil_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1ASN1Primitive *LibOrgBouncycastleX509ExtensionX509ExtensionUtil_fromExtensionValueWithByteArray_(IOSByteArray *encodedValue);

FOUNDATION_EXPORT id<JavaUtilCollection> LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getIssuerAlternativeNamesWithJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *cert);

FOUNDATION_EXPORT id<JavaUtilCollection> LibOrgBouncycastleX509ExtensionX509ExtensionUtil_getSubjectAlternativeNamesWithJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *cert);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleX509ExtensionX509ExtensionUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // X509ExtensionUtil_H
