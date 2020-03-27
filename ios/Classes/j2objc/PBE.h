//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/symmetric/util/PBE.java
//

#ifndef PBE_H
#define PBE_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaxCryptoSpecPBEKeySpec;
@class JavaxCryptoSpecPBEParameterSpec;
@class LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey;
@protocol JavaSecuritySpecAlgorithmParameterSpec;
@protocol JavaxCryptoSecretKey;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@protocol LibOrgBouncycastleJcajceProviderSymmetricUtilPBE < JavaObject >

@end

@interface LibOrgBouncycastleJcajceProviderSymmetricUtilPBE : NSObject
@property (readonly, class) jint MD5 NS_SWIFT_NAME(MD5);
@property (readonly, class) jint SHA1 NS_SWIFT_NAME(SHA1);
@property (readonly, class) jint RIPEMD160 NS_SWIFT_NAME(RIPEMD160);
@property (readonly, class) jint TIGER NS_SWIFT_NAME(TIGER);
@property (readonly, class) jint SHA256 NS_SWIFT_NAME(SHA256);
@property (readonly, class) jint MD2 NS_SWIFT_NAME(MD2);
@property (readonly, class) jint GOST3411 NS_SWIFT_NAME(GOST3411);
@property (readonly, class) jint SHA224 NS_SWIFT_NAME(SHA224);
@property (readonly, class) jint SHA384 NS_SWIFT_NAME(SHA384);
@property (readonly, class) jint SHA512 NS_SWIFT_NAME(SHA512);
@property (readonly, class) jint SHA3_224 NS_SWIFT_NAME(SHA3_224);
@property (readonly, class) jint SHA3_256 NS_SWIFT_NAME(SHA3_256);
@property (readonly, class) jint SHA3_384 NS_SWIFT_NAME(SHA3_384);
@property (readonly, class) jint SHA3_512 NS_SWIFT_NAME(SHA3_512);
@property (readonly, class) jint PKCS5S1 NS_SWIFT_NAME(PKCS5S1);
@property (readonly, class) jint PKCS5S2 NS_SWIFT_NAME(PKCS5S2);
@property (readonly, class) jint PKCS12 NS_SWIFT_NAME(PKCS12);
@property (readonly, class) jint OPENSSL NS_SWIFT_NAME(OPENSSL);
@property (readonly, class) jint PKCS5S1_UTF8 NS_SWIFT_NAME(PKCS5S1_UTF8);
@property (readonly, class) jint PKCS5S2_UTF8 NS_SWIFT_NAME(PKCS5S2_UTF8);

+ (jint)MD5;

+ (jint)SHA1;

+ (jint)RIPEMD160;

+ (jint)TIGER;

+ (jint)SHA256;

+ (jint)MD2;

+ (jint)GOST3411;

+ (jint)SHA224;

+ (jint)SHA384;

+ (jint)SHA512;

+ (jint)SHA3_224;

+ (jint)SHA3_256;

+ (jint)SHA3_384;

+ (jint)SHA3_512;

+ (jint)PKCS5S1;

+ (jint)PKCS5S2;

+ (jint)PKCS12;

+ (jint)OPENSSL;

+ (jint)PKCS5S1_UTF8;

+ (jint)PKCS5S2_UTF8;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_MD5(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_MD5 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, MD5, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_SHA1(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA1 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, SHA1, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_RIPEMD160(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_RIPEMD160 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, RIPEMD160, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_TIGER(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_TIGER 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, TIGER, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_SHA256(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA256 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, SHA256, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_MD2(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_MD2 5
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, MD2, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_GOST3411(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_GOST3411 6
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, GOST3411, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_SHA224(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA224 7
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, SHA224, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_SHA384(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA384 8
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, SHA384, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_SHA512(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA512 9
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, SHA512, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_SHA3_224(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA3_224 10
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, SHA3_224, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_SHA3_256(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA3_256 11
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, SHA3_256, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_SHA3_384(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA3_384 12
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, SHA3_384, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_SHA3_512(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_SHA3_512 13
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, SHA3_512, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_PKCS5S1(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS5S1 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, PKCS5S1, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_PKCS5S2(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS5S2 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, PKCS5S2, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_PKCS12(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS12 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, PKCS12, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_OPENSSL(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_OPENSSL 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, OPENSSL, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_PKCS5S1_UTF8(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS5S1_UTF8 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, PKCS5S1_UTF8, jint)

inline jint LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_get_PKCS5S2_UTF8(void);
#define LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_PKCS5S2_UTF8 5
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE, PKCS5S2_UTF8, jint)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE)

@interface LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (id<LibOrgBouncycastleCryptoCipherParameters>)makePBEMacParametersWithLibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey:(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *)pbeKey
                                                                                   withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)spec;

+ (id<LibOrgBouncycastleCryptoCipherParameters>)makePBEMacParametersWithJavaxCryptoSpecPBEKeySpec:(JavaxCryptoSpecPBEKeySpec *)keySpec
                                                                                          withInt:(jint)type
                                                                                          withInt:(jint)hash_
                                                                                          withInt:(jint)keySize;

+ (id<LibOrgBouncycastleCryptoCipherParameters>)makePBEMacParametersWithJavaxCryptoSecretKey:(id<JavaxCryptoSecretKey>)key
                                                                                     withInt:(jint)type
                                                                                     withInt:(jint)hash_
                                                                                     withInt:(jint)keySize
                                                         withJavaxCryptoSpecPBEParameterSpec:(JavaxCryptoSpecPBEParameterSpec *)pbeSpec;

+ (id<LibOrgBouncycastleCryptoCipherParameters>)makePBEParametersWithLibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey:(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *)pbeKey
                                                                                withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)spec
                                                                                                              withNSString:(NSString *)targetAlgorithm;

+ (id<LibOrgBouncycastleCryptoCipherParameters>)makePBEParametersWithByteArray:(IOSByteArray *)pbeKey
                                                                       withInt:(jint)scheme
                                                                       withInt:(jint)digest
                                                                       withInt:(jint)keySize
                                                                       withInt:(jint)ivSize
                                    withJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)spec
                                                                  withNSString:(NSString *)targetAlgorithm;

+ (id<LibOrgBouncycastleCryptoCipherParameters>)makePBEParametersWithJavaxCryptoSpecPBEKeySpec:(JavaxCryptoSpecPBEKeySpec *)keySpec
                                                                                       withInt:(jint)type
                                                                                       withInt:(jint)hash_
                                                                                       withInt:(jint)keySize
                                                                                       withInt:(jint)ivSize;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util_init(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util *new_LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util *create_LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util_init(void);

FOUNDATION_EXPORT id<LibOrgBouncycastleCryptoCipherParameters> LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util_makePBEParametersWithByteArray_withInt_withInt_withInt_withInt_withJavaSecuritySpecAlgorithmParameterSpec_withNSString_(IOSByteArray *pbeKey, jint scheme, jint digest, jint keySize, jint ivSize, id<JavaSecuritySpecAlgorithmParameterSpec> spec, NSString *targetAlgorithm);

FOUNDATION_EXPORT id<LibOrgBouncycastleCryptoCipherParameters> LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util_makePBEParametersWithLibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_withJavaSecuritySpecAlgorithmParameterSpec_withNSString_(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *pbeKey, id<JavaSecuritySpecAlgorithmParameterSpec> spec, NSString *targetAlgorithm);

FOUNDATION_EXPORT id<LibOrgBouncycastleCryptoCipherParameters> LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util_makePBEMacParametersWithLibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey_withJavaSecuritySpecAlgorithmParameterSpec_(LibOrgBouncycastleJcajceProviderSymmetricUtilBCPBEKey *pbeKey, id<JavaSecuritySpecAlgorithmParameterSpec> spec);

FOUNDATION_EXPORT id<LibOrgBouncycastleCryptoCipherParameters> LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util_makePBEMacParametersWithJavaxCryptoSpecPBEKeySpec_withInt_withInt_withInt_(JavaxCryptoSpecPBEKeySpec *keySpec, jint type, jint hash_, jint keySize);

FOUNDATION_EXPORT id<LibOrgBouncycastleCryptoCipherParameters> LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util_makePBEParametersWithJavaxCryptoSpecPBEKeySpec_withInt_withInt_withInt_withInt_(JavaxCryptoSpecPBEKeySpec *keySpec, jint type, jint hash_, jint keySize, jint ivSize);

FOUNDATION_EXPORT id<LibOrgBouncycastleCryptoCipherParameters> LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util_makePBEMacParametersWithJavaxCryptoSecretKey_withInt_withInt_withInt_withJavaxCryptoSpecPBEParameterSpec_(id<JavaxCryptoSecretKey> key, jint type, jint hash_, jint keySize, JavaxCryptoSpecPBEParameterSpec *pbeSpec);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderSymmetricUtilPBE_Util)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PBE_H