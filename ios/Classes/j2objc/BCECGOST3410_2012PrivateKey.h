//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/ecgost12/BCECGOST3410_2012PrivateKey.java
//

#ifndef BCECGOST3410_2012PrivateKey_H
#define BCECGOST3410_2012PrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ECPointEncoder.h"
#include "J2ObjC_header.h"
#include "JceECPrivateKey.h"
#include "PKCS12BagAttributeCarrier.h"
#include "java/security/interfaces/ECPrivateKey.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class JavaSecuritySpecECParameterSpec;
@class JavaSecuritySpecECPrivateKeySpec;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastleCryptoParamsECPrivateKeyParameters;
@class LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey;
@class LibOrgBouncycastleJceSpecECParameterSpec;
@class LibOrgBouncycastleJceSpecECPrivateKeySpec;
@protocol JavaUtilEnumeration;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey : NSObject < JavaSecurityInterfacesECPrivateKey, LibOrgBouncycastleJceInterfacesJceECPrivateKey, LibOrgBouncycastleJceInterfacesPKCS12BagAttributeCarrier, LibOrgBouncycastleJceInterfacesECPointEncoder >
@property (readonly, class) jlong serialVersionUID NS_SWIFT_NAME(serialVersionUID);

+ (jlong)serialVersionUID;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey:(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *)key;

- (instancetype __nonnull)initWithJavaSecurityInterfacesECPrivateKey:(id<JavaSecurityInterfacesECPrivateKey>)key;

- (instancetype __nonnull)initWithLibOrgBouncycastleJceSpecECPrivateKeySpec:(LibOrgBouncycastleJceSpecECPrivateKeySpec *)spec;

- (instancetype __nonnull)initWithJavaSecuritySpecECPrivateKeySpec:(JavaSecuritySpecECPrivateKeySpec *)spec;

- (instancetype __nonnull)initWithNSString:(NSString *)algorithm
withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)params;

- (instancetype __nonnull)initWithNSString:(NSString *)algorithm
withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)params
withLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey:(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey *)pubKey
       withJavaSecuritySpecECParameterSpec:(JavaSecuritySpecECParameterSpec *)spec;

- (instancetype __nonnull)initWithNSString:(NSString *)algorithm
withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)params
withLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey:(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey *)pubKey
withLibOrgBouncycastleJceSpecECParameterSpec:(LibOrgBouncycastleJceSpecECParameterSpec *)spec;

- (jboolean)isEqual:(id)o;

- (NSString *)getAlgorithm;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

- (id<JavaUtilEnumeration>)getBagAttributeKeys;

- (JavaMathBigInteger *)getD;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (LibOrgBouncycastleJceSpecECParameterSpec *)getParameters;

- (JavaSecuritySpecECParameterSpec *)getParams;

- (JavaMathBigInteger *)getS;

- (NSUInteger)hash;

- (void)setBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                              withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)attribute;

- (void)setPointFormatWithNSString:(NSString *)style;

- (NSString *)description;

#pragma mark Protected

- (instancetype __nonnull)init;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)info;

- (LibOrgBouncycastleJceSpecECParameterSpec *)engineGetSpec;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey)

inline jlong LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_get_serialVersionUID(void);
#define LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_serialVersionUID 7245981689601667138LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey, serialVersionUID, jlong)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_init(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithJavaSecurityInterfacesECPrivateKey_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *self, id<JavaSecurityInterfacesECPrivateKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithJavaSecurityInterfacesECPrivateKey_(id<JavaSecurityInterfacesECPrivateKey> key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithJavaSecurityInterfacesECPrivateKey_(id<JavaSecurityInterfacesECPrivateKey> key);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithLibOrgBouncycastleJceSpecECPrivateKeySpec_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *self, LibOrgBouncycastleJceSpecECPrivateKeySpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithLibOrgBouncycastleJceSpecECPrivateKeySpec_(LibOrgBouncycastleJceSpecECPrivateKeySpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithLibOrgBouncycastleJceSpecECPrivateKeySpec_(LibOrgBouncycastleJceSpecECPrivateKeySpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithJavaSecuritySpecECPrivateKeySpec_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *self, JavaSecuritySpecECPrivateKeySpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithJavaSecuritySpecECPrivateKeySpec_(JavaSecuritySpecECPrivateKeySpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithJavaSecuritySpecECPrivateKeySpec_(JavaSecuritySpecECPrivateKeySpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *self, LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *key);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *key);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey_withJavaSecuritySpecECParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *self, NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey *pubKey, JavaSecuritySpecECParameterSpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey_withJavaSecuritySpecECParameterSpec_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey *pubKey, JavaSecuritySpecECParameterSpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey_withJavaSecuritySpecECParameterSpec_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey *pubKey, JavaSecuritySpecECParameterSpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey_withLibOrgBouncycastleJceSpecECParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *self, NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey *pubKey, LibOrgBouncycastleJceSpecECParameterSpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey_withLibOrgBouncycastleJceSpecECParameterSpec_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey *pubKey, LibOrgBouncycastleJceSpecECParameterSpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey_withLibOrgBouncycastleJceSpecECParameterSpec_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PublicKey *pubKey, LibOrgBouncycastleJceSpecECParameterSpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *self, NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *self, LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcgost12BCECGOST3410_2012PrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BCECGOST3410_2012PrivateKey_H