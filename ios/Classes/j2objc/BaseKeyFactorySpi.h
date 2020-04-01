//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/util/BaseKeyFactorySpi.java
//

#ifndef BaseKeyFactorySpi_H
#define BaseKeyFactorySpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricKeyInfoConverter.h"
#include "J2ObjC_header.h"
#include "java/security/KeyFactorySpi.h"

@class IOSClass;
@protocol JavaSecurityKey;
@protocol JavaSecurityPrivateKey;
@protocol JavaSecurityPublicKey;
@protocol JavaSecuritySpecKeySpec;

@interface LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi : JavaSecurityKeyFactorySpi < LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter >

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)spec;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi_init(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricUtilBaseKeyFactorySpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BaseKeyFactorySpi_H