//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/Ed448PrivateKeyParameters.java
//

#ifndef Ed448PrivateKeyParameters_H
#define Ed448PrivateKeyParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "AsymmetricKeyParameter.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoParamsEd448PublicKeyParameters;

@interface LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters : LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter
@property (readonly, class) jint KEY_SIZE NS_SWIFT_NAME(KEY_SIZE);
@property (readonly, class) jint SIGNATURE_SIZE NS_SWIFT_NAME(SIGNATURE_SIZE);

+ (jint)KEY_SIZE;

+ (jint)SIGNATURE_SIZE;

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)buf
                                    withInt:(jint)off;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)input;

- (instancetype __nonnull)initWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

- (void)encodeWithByteArray:(IOSByteArray *)buf
                    withInt:(jint)off;

- (LibOrgBouncycastleCryptoParamsEd448PublicKeyParameters *)generatePublicKey;

- (IOSByteArray *)getEncoded;

- (void)signWithInt:(jint)algorithm
withLibOrgBouncycastleCryptoParamsEd448PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd448PublicKeyParameters *)publicKey
      withByteArray:(IOSByteArray *)ctx
      withByteArray:(IOSByteArray *)msg
            withInt:(jint)msgOff
            withInt:(jint)msgLen
      withByteArray:(IOSByteArray *)sig
            withInt:(jint)sigOff;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters)

inline jint LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_get_KEY_SIZE(void);
#define LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_KEY_SIZE 57
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters, KEY_SIZE, jint)

inline jint LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_get_SIGNATURE_SIZE(void);
#define LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_SIGNATURE_SIZE 114
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters, SIGNATURE_SIZE, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *self, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithByteArray_withInt_(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *self, IOSByteArray *buf, jint off);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaIoInputStream_(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *self, JavaIoInputStream *input);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsEd448PrivateKeyParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Ed448PrivateKeyParameters_H
