//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dsa/JcajceDsaKeyFactorySpi.java
//

#ifndef JcajceDsaKeyFactorySpi_H
#define JcajceDsaKeyFactorySpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BaseKeyFactorySpi.h"
#include "J2ObjC_header.h"

@class IOSClass;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@protocol JavaSecurityKey;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecKeySpec;

@interface LibOrgBouncycastleJcajceProviderAsymmetricDsaJcajceDsaKeyFactorySpi : LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi

#pragma mark Public

- (instancetype __nonnull)init;

- (id<JavaSecurityPrivateKey>)generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)keyInfo;

- (id<JavaSecurityPublicKey>)generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo;

#pragma mark Protected

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)spec;

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricDsaJcajceDsaKeyFactorySpi)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricDsaJcajceDsaKeyFactorySpi_init(LibOrgBouncycastleJcajceProviderAsymmetricDsaJcajceDsaKeyFactorySpi *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDsaJcajceDsaKeyFactorySpi *new_LibOrgBouncycastleJcajceProviderAsymmetricDsaJcajceDsaKeyFactorySpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricDsaJcajceDsaKeyFactorySpi *create_LibOrgBouncycastleJcajceProviderAsymmetricDsaJcajceDsaKeyFactorySpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricDsaJcajceDsaKeyFactorySpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceDsaKeyFactorySpi_H
