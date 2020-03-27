//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/rsa/BCRSAPublicKey.java
//

#ifndef BCRSAPublicKey_H
#define BCRSAPublicKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/interfaces/RSAPublicKey.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaSecuritySpecRSAPublicKeySpec;
@class LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo;
@class LibOrgBouncycastleCryptoParamsRSAKeyParameters;

@interface LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey : NSObject < JavaSecurityInterfacesRSAPublicKey >
@property (readonly, class) jlong serialVersionUID NS_SWIFT_NAME(serialVersionUID);

+ (jlong)serialVersionUID;

#pragma mark Public

- (jboolean)isEqual:(id)o;

- (NSString *)getAlgorithm;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (JavaMathBigInteger *)getModulus;

- (JavaMathBigInteger *)getPublicExponent;

- (NSUInteger)hash;

- (NSString *)description;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters:(LibOrgBouncycastleCryptoParamsRSAKeyParameters *)key;

- (instancetype __nonnull)initWithJavaSecurityInterfacesRSAPublicKey:(id<JavaSecurityInterfacesRSAPublicKey>)key;

- (instancetype __nonnull)initWithJavaSecuritySpecRSAPublicKeySpec:(JavaSecuritySpecRSAPublicKeySpec *)spec;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo:(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *)info;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey)

inline jlong LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_get_serialVersionUID(void);
#define LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_serialVersionUID 2675817738516720772LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey, serialVersionUID, jlong)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *self, LibOrgBouncycastleCryptoParamsRSAKeyParameters *key);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleCryptoParamsRSAKeyParameters *key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithLibOrgBouncycastleCryptoParamsRSAKeyParameters_(LibOrgBouncycastleCryptoParamsRSAKeyParameters *key);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithJavaSecuritySpecRSAPublicKeySpec_(LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *self, JavaSecuritySpecRSAPublicKeySpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithJavaSecuritySpecRSAPublicKeySpec_(JavaSecuritySpecRSAPublicKeySpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithJavaSecuritySpecRSAPublicKeySpec_(JavaSecuritySpecRSAPublicKeySpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithJavaSecurityInterfacesRSAPublicKey_(LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *self, id<JavaSecurityInterfacesRSAPublicKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithJavaSecurityInterfacesRSAPublicKey_(id<JavaSecurityInterfacesRSAPublicKey> key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithJavaSecurityInterfacesRSAPublicKey_(id<JavaSecurityInterfacesRSAPublicKey> key);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *self, LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey_initWithLibOrgBouncycastleAsn1X509SubjectPublicKeyInfo_(LibOrgBouncycastleAsn1X509SubjectPublicKeyInfo *info);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricRsaBCRSAPublicKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BCRSAPublicKey_H
