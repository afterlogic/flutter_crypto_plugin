//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/ecgost/BCECGOST3410PrivateKey.java
//

#ifndef BCECGOST3410PrivateKey_H
#define BCECGOST3410PrivateKey_H

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
@class LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey;
@class LibOrgBouncycastleJceSpecECParameterSpec;
@class LibOrgBouncycastleJceSpecECPrivateKeySpec;
@protocol JavaUtilEnumeration;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey : NSObject < JavaSecurityInterfacesECPrivateKey, LibOrgBouncycastleJceInterfacesJceECPrivateKey, LibOrgBouncycastleJceInterfacesPKCS12BagAttributeCarrier, LibOrgBouncycastleJceInterfacesECPointEncoder >
@property (readonly, class) jlong serialVersionUID NS_SWIFT_NAME(serialVersionUID);

+ (jlong)serialVersionUID;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey:(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *)key;

- (instancetype __nonnull)initWithJavaSecurityInterfacesECPrivateKey:(id<JavaSecurityInterfacesECPrivateKey>)key;

- (instancetype __nonnull)initWithLibOrgBouncycastleJceSpecECPrivateKeySpec:(LibOrgBouncycastleJceSpecECPrivateKeySpec *)spec;

- (instancetype __nonnull)initWithJavaSecuritySpecECPrivateKeySpec:(JavaSecuritySpecECPrivateKeySpec *)spec;

- (instancetype __nonnull)initWithNSString:(NSString *)algorithm
withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)params;

- (instancetype __nonnull)initWithNSString:(NSString *)algorithm
withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)params
withLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey:(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey *)pubKey
       withJavaSecuritySpecECParameterSpec:(JavaSecuritySpecECParameterSpec *)spec;

- (instancetype __nonnull)initWithNSString:(NSString *)algorithm
withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters:(LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *)params
withLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey:(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey *)pubKey
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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey)

inline jlong LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_get_serialVersionUID(void);
#define LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_serialVersionUID 7245981689601667138LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey, serialVersionUID, jlong)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_init(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithJavaSecurityInterfacesECPrivateKey_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *self, id<JavaSecurityInterfacesECPrivateKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithJavaSecurityInterfacesECPrivateKey_(id<JavaSecurityInterfacesECPrivateKey> key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithJavaSecurityInterfacesECPrivateKey_(id<JavaSecurityInterfacesECPrivateKey> key);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithLibOrgBouncycastleJceSpecECPrivateKeySpec_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *self, LibOrgBouncycastleJceSpecECPrivateKeySpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithLibOrgBouncycastleJceSpecECPrivateKeySpec_(LibOrgBouncycastleJceSpecECPrivateKeySpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithLibOrgBouncycastleJceSpecECPrivateKeySpec_(LibOrgBouncycastleJceSpecECPrivateKeySpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithJavaSecuritySpecECPrivateKeySpec_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *self, JavaSecuritySpecECPrivateKeySpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithJavaSecuritySpecECPrivateKeySpec_(JavaSecuritySpecECPrivateKeySpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithJavaSecuritySpecECPrivateKeySpec_(JavaSecuritySpecECPrivateKeySpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *self, LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *key);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *key);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey_withJavaSecuritySpecECParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *self, NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey *pubKey, JavaSecuritySpecECParameterSpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey_withJavaSecuritySpecECParameterSpec_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey *pubKey, JavaSecuritySpecECParameterSpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey_withJavaSecuritySpecECParameterSpec_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey *pubKey, JavaSecuritySpecECParameterSpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey_withLibOrgBouncycastleJceSpecECParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *self, NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey *pubKey, LibOrgBouncycastleJceSpecECParameterSpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey_withLibOrgBouncycastleJceSpecECParameterSpec_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey *pubKey, LibOrgBouncycastleJceSpecECParameterSpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_withLibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey_withLibOrgBouncycastleJceSpecECParameterSpec_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params, LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PublicKey *pubKey, LibOrgBouncycastleJceSpecECParameterSpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *self, NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithNSString_withLibOrgBouncycastleCryptoParamsECPrivateKeyParameters_(NSString *algorithm, LibOrgBouncycastleCryptoParamsECPrivateKeyParameters *params);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *self, LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcgostBCECGOST3410PrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BCECGOST3410PrivateKey_H