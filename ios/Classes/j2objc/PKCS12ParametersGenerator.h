//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/PKCS12ParametersGenerator.java
//

#ifndef PKCS12ParametersGenerator_H
#define PKCS12ParametersGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PBEParametersGenerator.h"

@protocol LibOrgBouncycastleCryptoCipherParameters;
@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator : LibOrgBouncycastleCryptoPBEParametersGenerator
@property (readonly, class) jint KEY_MATERIAL NS_SWIFT_NAME(KEY_MATERIAL);
@property (readonly, class) jint IV_MATERIAL NS_SWIFT_NAME(IV_MATERIAL);
@property (readonly, class) jint MAC_MATERIAL NS_SWIFT_NAME(MAC_MATERIAL);

+ (jint)KEY_MATERIAL;

+ (jint)IV_MATERIAL;

+ (jint)MAC_MATERIAL;

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedMacParametersWithInt:(jint)keySize;

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize;

- (id<LibOrgBouncycastleCryptoCipherParameters>)generateDerivedParametersWithInt:(jint)keySize
                                                                         withInt:(jint)ivSize;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator)

inline jint LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_get_KEY_MATERIAL(void);
#define LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_KEY_MATERIAL 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator, KEY_MATERIAL, jint)

inline jint LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_get_IV_MATERIAL(void);
#define LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_IV_MATERIAL 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator, IV_MATERIAL, jint)

inline jint LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_get_MAC_MATERIAL(void);
#define LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_MAC_MATERIAL 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator, MAC_MATERIAL, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator *self, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator *new_LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator *create_LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsPKCS12ParametersGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PKCS12ParametersGenerator_H
