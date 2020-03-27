//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/mceliece/McElieceCCA2KeyFactorySpi.java
//

#ifndef McElieceCCA2KeyFactorySpi_H
#define McElieceCCA2KeyFactorySpi_H

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

@interface LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi : JavaSecurityKeyFactorySpi < LibOrgBouncycastleJcajceProviderUtilAsymmetricKeyInfoConverter >
@property (readonly, copy, class) NSString *OID NS_SWIFT_NAME(OID);

+ (NSString *)OID;

#pragma mark Public

- (instancetype __nonnull)init;

- (id<JavaSecurityPrivateKey>)generatePrivateWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)pki;

- (id<JavaSecurityPublicKey>)generatePublicWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)pki;

- (id<JavaSecuritySpecKeySpec>)getKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                withIOSClass:(IOSClass *)keySpec;

- (id<JavaSecurityKey>)translateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key;

#pragma mark Protected

- (id<JavaSecurityPrivateKey>)engineGeneratePrivateWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecurityPublicKey>)engineGeneratePublicWithJavaSecuritySpecKeySpec:(id<JavaSecuritySpecKeySpec>)keySpec;

- (id<JavaSecuritySpecKeySpec>)engineGetKeySpecWithJavaSecurityKey:(id<JavaSecurityKey>)key
                                                      withIOSClass:(IOSClass *)tClass;

- (id<JavaSecurityKey>)engineTranslateKeyWithJavaSecurityKey:(id<JavaSecurityKey>)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi)

inline NSString *LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi_get_OID(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT NSString *LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi_OID;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi, OID, NSString *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi_init(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi *new_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi *create_LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderMcelieceMcElieceCCA2KeyFactorySpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // McElieceCCA2KeyFactorySpi_H