//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/params/Ed25519PrivateKeyParameters.java
//

#ifndef Ed25519PrivateKeyParameters_H
#define Ed25519PrivateKeyParameters_H

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
@class LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters;

@interface LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters : LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter
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

- (LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)generatePublicKey;

- (IOSByteArray *)getEncoded;

- (void)signWithInt:(jint)algorithm
withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)publicKey
      withByteArray:(IOSByteArray *)ctx
      withByteArray:(IOSByteArray *)msg
            withInt:(jint)msgOff
            withInt:(jint)msgLen
      withByteArray:(IOSByteArray *)sig
            withInt:(jint)sigOff;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithBoolean:(jboolean)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters)

inline jint LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_get_KEY_SIZE(void);
#define LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_KEY_SIZE 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters, KEY_SIZE, jint)

inline jint LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_get_SIGNATURE_SIZE(void);
#define LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_SIGNATURE_SIZE 64
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters, SIGNATURE_SIZE, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *self, JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_initWithJavaSecuritySecureRandom_(JavaSecuritySecureRandom *random);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_initWithByteArray_withInt_(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *self, IOSByteArray *buf, jint off);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_initWithByteArray_withInt_(IOSByteArray *buf, jint off);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_initWithJavaIoInputStream_(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *self, JavaIoInputStream *input);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *new_LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *create_LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_initWithJavaIoInputStream_(JavaIoInputStream *input);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Ed25519PrivateKeyParameters_H
