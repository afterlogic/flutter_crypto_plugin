//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/SecretSubkeyPacket.java
//

#ifndef SecretSubkeyPacket_H
#define SecretSubkeyPacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "SecretKeyPacket.h"

@class IOSByteArray;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgBCPGOutputStream;
@class LibOrgBouncycastleBcpgPublicKeyPacket;
@class LibOrgBouncycastleBcpgS2K;

@interface LibOrgBouncycastleBcpgSecretSubkeyPacket : LibOrgBouncycastleBcpgSecretKeyPacket

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgPublicKeyPacket:(LibOrgBouncycastleBcpgPublicKeyPacket *)pubKeyPacket
                                                                withInt:(jint)encAlgorithm
                                                                withInt:(jint)s2kUsage
                                          withLibOrgBouncycastleBcpgS2K:(LibOrgBouncycastleBcpgS2K *)s2k
                                                          withByteArray:(IOSByteArray *)iv
                                                          withByteArray:(IOSByteArray *)secKeyData;

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgPublicKeyPacket:(LibOrgBouncycastleBcpgPublicKeyPacket *)pubKeyPacket
                                                                withInt:(jint)encAlgorithm
                                          withLibOrgBouncycastleBcpgS2K:(LibOrgBouncycastleBcpgS2K *)s2k
                                                          withByteArray:(IOSByteArray *)iv
                                                          withByteArray:(IOSByteArray *)secKeyData;

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgSecretSubkeyPacket)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSecretSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgSecretSubkeyPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretSubkeyPacket *new_LibOrgBouncycastleBcpgSecretSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretSubkeyPacket *create_LibOrgBouncycastleBcpgSecretSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSecretSubkeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgSecretSubkeyPacket *self, LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretSubkeyPacket *new_LibOrgBouncycastleBcpgSecretSubkeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretSubkeyPacket *create_LibOrgBouncycastleBcpgSecretSubkeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSecretSubkeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgSecretSubkeyPacket *self, LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, jint s2kUsage, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretSubkeyPacket *new_LibOrgBouncycastleBcpgSecretSubkeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, jint s2kUsage, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSecretSubkeyPacket *create_LibOrgBouncycastleBcpgSecretSubkeyPacket_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withInt_withInt_withLibOrgBouncycastleBcpgS2K_withByteArray_withByteArray_(LibOrgBouncycastleBcpgPublicKeyPacket *pubKeyPacket, jint encAlgorithm, jint s2kUsage, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *iv, IOSByteArray *secKeyData);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgSecretSubkeyPacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SecretSubkeyPacket_H
