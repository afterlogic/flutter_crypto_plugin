//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/jcajce/provider/rainbow/RainbowKeyPairGeneratorSpi.java
//

#ifndef RainbowKeyPairGeneratorSpi_H
#define RainbowKeyPairGeneratorSpi_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/security/KeyPairGenerator.h"

@class JavaSecurityKeyPair;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastlePqcCryptoRainbowRainbowKeyGenerationParameters;
@class LibOrgBouncycastlePqcCryptoRainbowRainbowKeyPairGenerator;
@protocol JavaSecuritySpecAlgorithmParameterSpec;

@interface LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi : JavaSecurityKeyPairGenerator {
 @public
  LibOrgBouncycastlePqcCryptoRainbowRainbowKeyGenerationParameters *param_;
  LibOrgBouncycastlePqcCryptoRainbowRainbowKeyPairGenerator *engine_;
  jint strength_;
  JavaSecuritySecureRandom *random_;
  jboolean initialised_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (JavaSecurityKeyPair *)generateKeyPair;

- (void)initialize__WithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)params
                                  withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

- (void)initialize__WithInt:(jint)strength
withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random OBJC_METHOD_FAMILY_NONE;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi)

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi, param_, LibOrgBouncycastlePqcCryptoRainbowRainbowKeyGenerationParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi, engine_, LibOrgBouncycastlePqcCryptoRainbowRainbowKeyPairGenerator *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi, random_, JavaSecuritySecureRandom *)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi_init(LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi *new_LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi *create_LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcJcajceProviderRainbowRainbowKeyPairGeneratorSpi)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RainbowKeyPairGeneratorSpi_H
