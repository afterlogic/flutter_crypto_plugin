//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/sphincs/Sphincs256KeyFactorySpi.java
//

#ifndef Sphincs256KeyFactorySpi_H
#define Sphincs256KeyFactorySpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricKeyInfoConverter.h"
#include "J2ObjC_header.h"
#include "java/security/KeyFactorySpi.h"

@class IOSClass;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@protocol JavaSecurityKey;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecKeySpec;

@interface LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyFactorySpi : JavaSecurityKeyFactorySpi < LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter >

#pragma mark Public

- (instancetype __nonnull)init;

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)keySpec;

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key;

- (id<JavaSecurityPrivateKey>)generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)keyInfo;

- (id<JavaSecurityPublicKey>)generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)keyInfo;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyFactorySpi)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyFactorySpi_init(LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyFactorySpi *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyFactorySpi *new_LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyFactorySpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyFactorySpi *create_LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyFactorySpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderSphincsSphincs256KeyFactorySpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Sphincs256KeyFactorySpi_H