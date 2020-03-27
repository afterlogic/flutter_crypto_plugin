//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/ec/ECUtils.java
//

#ifndef ECUtils_H
#define ECUtils_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaSecuritySpecECGenParameterSpec;
@class JavaSecuritySpecECParameterSpec;
@class LibOrgBouncycastleAsn1X9X962Parameters;
@class LibOrgBouncycastleAsn1X9X9ECParameters;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;
@protocol JavaSecurityPublicKey;

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils : NSObject

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)generatePublicKeyParameterWithJavaSecurityPublicKey:(id<JavaSecurityPublicKey>)key;

+ (LibOrgBouncycastleAsn1X9X9ECParameters *)getDomainParametersFromGenSpecWithJavaSecuritySpecECGenParameterSpec:(JavaSecuritySpecECGenParameterSpec *)genSpec;

+ (LibOrgBouncycastleAsn1X9X962Parameters *)getDomainParametersFromNameWithJavaSecuritySpecECParameterSpec:(JavaSecuritySpecECParameterSpec *)ecSpec
                                                                                               withBoolean:(jboolean)withCompression;

+ (LibOrgBouncycastleAsn1X9X9ECParameters *)getDomainParametersFromNameWithNSString:(NSString *)curveName;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils_init(LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils *new_LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils *create_LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils_generatePublicKeyParameterWithJavaSecurityPublicKey_(id<JavaSecurityPublicKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParameters *LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils_getDomainParametersFromGenSpecWithJavaSecuritySpecECGenParameterSpec_(JavaSecuritySpecECGenParameterSpec *genSpec);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X9ECParameters *LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils_getDomainParametersFromNameWithNSString_(NSString *curveName);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1X9X962Parameters *LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils_getDomainParametersFromNameWithJavaSecuritySpecECParameterSpec_withBoolean_(JavaSecuritySpecECParameterSpec *ecSpec, jboolean withCompression);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECUtils_H
