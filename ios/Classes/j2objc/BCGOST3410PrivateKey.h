//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/gost/BCGOST3410PrivateKey.java
//

#ifndef BCGOST3410PrivateKey_H
#define BCGOST3410PrivateKey_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "GOST3410PrivateKey.h"
#include "J2ObjC_header.h"
#include "PKCS12BagAttributeCarrier.h"

@class IOSByteArray;
@class JavaMathBigInteger;
@class LibOrgBouncycastleAsn1ASN1ObjectIdentifier;
@class LibOrgBouncycastleAsn1PkcsPrivateKeyInfo;
@class LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters;
@class LibOrgBouncycastleJceSpecGOST3410ParameterSpec;
@class LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec;
@protocol JavaUtilEnumeration;
@protocol LibOrgBouncycastleAsn1ASN1Encodable;
@protocol LibOrgBouncycastleJceInterfacesGOST3410Params;

@interface LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey : NSObject < LibOrgBouncycastleJceInterfacesGOST3410PrivateKey, LibOrgBouncycastleJceInterfacesPKCS12BagAttributeCarrier >
@property (readonly, class) jlong serialVersionUID NS_SWIFT_NAME(serialVersionUID);

+ (jlong)serialVersionUID;

#pragma mark Public

- (jboolean)isEqual:(id)o;

- (NSString *)getAlgorithm;

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)getBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid;

- (id<JavaUtilEnumeration>)getBagAttributeKeys;

- (IOSByteArray *)getEncoded;

- (NSString *)getFormat;

- (id<LibOrgBouncycastleJceInterfacesGOST3410Params>)getParameters;

- (JavaMathBigInteger *)getX;

- (NSUInteger)hash;

- (void)setBagAttributeWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                              withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)attribute;

- (NSString *)description;

#pragma mark Protected

- (instancetype __nonnull)init;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleJceInterfacesGOST3410PrivateKey:(id<LibOrgBouncycastleJceInterfacesGOST3410PrivateKey>)key;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters:(LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters *)params
                                          withLibOrgBouncycastleJceSpecGOST3410ParameterSpec:(LibOrgBouncycastleJceSpecGOST3410ParameterSpec *)spec;

- (instancetype __nonnull)initWithLibOrgBouncycastleJceSpecGOST3410PrivateKeySpec:(LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec *)spec;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo:(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *)info;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey)

inline jlong LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_get_serialVersionUID(void);
#define LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_serialVersionUID 8581661527592305464LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey, serialVersionUID, jlong)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_init(LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleJceInterfacesGOST3410PrivateKey_(LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *self, id<LibOrgBouncycastleJceInterfacesGOST3410PrivateKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleJceInterfacesGOST3410PrivateKey_(id<LibOrgBouncycastleJceInterfacesGOST3410PrivateKey> key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleJceInterfacesGOST3410PrivateKey_(id<LibOrgBouncycastleJceInterfacesGOST3410PrivateKey> key);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleJceSpecGOST3410PrivateKeySpec_(LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *self, LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleJceSpecGOST3410PrivateKeySpec_(LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleJceSpecGOST3410PrivateKeySpec_(LibOrgBouncycastleJceSpecGOST3410PrivateKeySpec *spec);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *self, LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleAsn1PkcsPrivateKeyInfo_(LibOrgBouncycastleAsn1PkcsPrivateKeyInfo *info);

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters_withLibOrgBouncycastleJceSpecGOST3410ParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *self, LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters *params, LibOrgBouncycastleJceSpecGOST3410ParameterSpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *new_LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters_withLibOrgBouncycastleJceSpecGOST3410ParameterSpec_(LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters *params, LibOrgBouncycastleJceSpecGOST3410ParameterSpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey *create_LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey_initWithLibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters_withLibOrgBouncycastleJceSpecGOST3410ParameterSpec_(LibOrgBouncycastleCryptoParamsGOST3410PrivateKeyParameters *params, LibOrgBouncycastleJceSpecGOST3410ParameterSpec *spec);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricGostBCGOST3410PrivateKey)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BCGOST3410PrivateKey_H