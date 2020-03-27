//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/config/JcajceConfigPKCS12StoreParameter.java
//

#ifndef JcajceConfigPKCS12StoreParameter_H
#define JcajceConfigPKCS12StoreParameter_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PKCS12StoreParameter.h"

@class IOSCharArray;
@class JavaIoOutputStream;
@protocol JavaSecurityKeyStore_ProtectionParameter;

@interface LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter : LibOrgBouncycastleJcajcePKCS12StoreParameter

#pragma mark Public

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                       withCharArray:(IOSCharArray *)password;

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                       withCharArray:(IOSCharArray *)password
                                         withBoolean:(jboolean)forDEREncoding;

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
        withJavaSecurityKeyStore_ProtectionParameter:(id<JavaSecurityKeyStore_ProtectionParameter>)protectionParameter;

- (instancetype __nonnull)initWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
        withJavaSecurityKeyStore_ProtectionParameter:(id<JavaSecurityKeyStore_ProtectionParameter>)protectionParameter
                                         withBoolean:(jboolean)forDEREncoding;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_(LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *self, JavaIoOutputStream *outArg, IOSCharArray *password);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *new_LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_(JavaIoOutputStream *outArg, IOSCharArray *password) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *create_LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_(JavaIoOutputStream *outArg, IOSCharArray *password);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *self, JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *new_LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *create_LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *self, JavaIoOutputStream *outArg, IOSCharArray *password, jboolean forDEREncoding);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *new_LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(JavaIoOutputStream *outArg, IOSCharArray *password, jboolean forDEREncoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *create_LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withCharArray_withBoolean_(JavaIoOutputStream *outArg, IOSCharArray *password, jboolean forDEREncoding);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *self, JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter, jboolean forDEREncoding);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *new_LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter, jboolean forDEREncoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter *create_LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter_initWithJavaIoOutputStream_withJavaSecurityKeyStore_ProtectionParameter_withBoolean_(JavaIoOutputStream *outArg, id<JavaSecurityKeyStore_ProtectionParameter> protectionParameter, jboolean forDEREncoding);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderConfigJcajceConfigPKCS12StoreParameter)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceConfigPKCS12StoreParameter_H