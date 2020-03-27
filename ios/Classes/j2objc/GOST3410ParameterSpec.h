//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/GOST3410ParameterSpec.java
//

#ifndef GOST3410ParameterSpec_H
#define GOST3410ParameterSpec_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "GOST3410Params.h"
#include "J2ObjC_header.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@class LibOrgBouncycastleAsn1CryptoproGOST3410PublicKeyAlgParameters;
@class LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec;

@interface LibOrgBouncycastleJceSpecGOST3410ParameterSpec : NSObject < JavaSecuritySpecAlgorithmParameterSpec, LibOrgBouncycastleJceInterfacesGOST3410Params >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec:(LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *)spec;

- (instancetype __nonnull)initWithNSString:(NSString *)keyParamSetID;

- (instancetype __nonnull)initWithNSString:(NSString *)keyParamSetID
                              withNSString:(NSString *)digestParamSetOID;

- (instancetype __nonnull)initWithNSString:(NSString *)keyParamSetID
                              withNSString:(NSString *)digestParamSetOID
                              withNSString:(NSString *)encryptionParamSetOID;

- (jboolean)isEqual:(id)o;

+ (LibOrgBouncycastleJceSpecGOST3410ParameterSpec *)fromPublicKeyAlgWithLibOrgBouncycastleAsn1CryptoproGOST3410PublicKeyAlgParameters:(LibOrgBouncycastleAsn1CryptoproGOST3410PublicKeyAlgParameters *)params;

- (NSString *)getDigestParamSetOID;

- (NSString *)getEncryptionParamSetOID;

- (LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *)getPublicKeyParameters;

- (NSString *)getPublicKeyParamSetOID;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceSpecGOST3410ParameterSpec)

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithNSString_withNSString_withNSString_(LibOrgBouncycastleJceSpecGOST3410ParameterSpec *self, NSString *keyParamSetID, NSString *digestParamSetOID, NSString *encryptionParamSetOID);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410ParameterSpec *new_LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithNSString_withNSString_withNSString_(NSString *keyParamSetID, NSString *digestParamSetOID, NSString *encryptionParamSetOID) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410ParameterSpec *create_LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithNSString_withNSString_withNSString_(NSString *keyParamSetID, NSString *digestParamSetOID, NSString *encryptionParamSetOID);

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithNSString_withNSString_(LibOrgBouncycastleJceSpecGOST3410ParameterSpec *self, NSString *keyParamSetID, NSString *digestParamSetOID);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410ParameterSpec *new_LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithNSString_withNSString_(NSString *keyParamSetID, NSString *digestParamSetOID) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410ParameterSpec *create_LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithNSString_withNSString_(NSString *keyParamSetID, NSString *digestParamSetOID);

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithNSString_(LibOrgBouncycastleJceSpecGOST3410ParameterSpec *self, NSString *keyParamSetID);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410ParameterSpec *new_LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithNSString_(NSString *keyParamSetID) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410ParameterSpec *create_LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithNSString_(NSString *keyParamSetID);

FOUNDATION_EXPORT void LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithLibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec_(LibOrgBouncycastleJceSpecGOST3410ParameterSpec *self, LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410ParameterSpec *new_LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithLibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec_(LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *spec) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410ParameterSpec *create_LibOrgBouncycastleJceSpecGOST3410ParameterSpec_initWithLibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec_(LibOrgBouncycastleJceSpecGOST3410PublicKeyParameterSetSpec *spec);

FOUNDATION_EXPORT LibOrgBouncycastleJceSpecGOST3410ParameterSpec *LibOrgBouncycastleJceSpecGOST3410ParameterSpec_fromPublicKeyAlgWithLibOrgBouncycastleAsn1CryptoproGOST3410PublicKeyAlgParameters_(LibOrgBouncycastleAsn1CryptoproGOST3410PublicKeyAlgParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceSpecGOST3410ParameterSpec)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // GOST3410ParameterSpec_H