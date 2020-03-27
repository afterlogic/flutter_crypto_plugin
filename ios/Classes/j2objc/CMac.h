//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/macs/CMac.java
//

#ifndef CMac_H
#define CMac_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Mac.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoMacsCMac : NSObject < LibOrgBouncycastleCryptoMac >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher
                                                              withInt:(jint)macSizeInBits;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (NSString *)getAlgorithmName;

- (jint)getMacSize;

- (void)init__WithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (void)reset;

- (void)updateWithByte:(jbyte)inArg;

- (void)updateWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)len;

#pragma mark Package-Private

- (void)validateWithLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoMacsCMac)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoMacsCMac_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoMacsCMac *self, id<LibOrgBouncycastleCryptoBlockCipher> cipher);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoMacsCMac *new_LibOrgBouncycastleCryptoMacsCMac_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoMacsCMac *create_LibOrgBouncycastleCryptoMacsCMac_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoMacsCMac_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(LibOrgBouncycastleCryptoMacsCMac *self, id<LibOrgBouncycastleCryptoBlockCipher> cipher, jint macSizeInBits);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoMacsCMac *new_LibOrgBouncycastleCryptoMacsCMac_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(id<LibOrgBouncycastleCryptoBlockCipher> cipher, jint macSizeInBits) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoMacsCMac *create_LibOrgBouncycastleCryptoMacsCMac_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(id<LibOrgBouncycastleCryptoBlockCipher> cipher, jint macSizeInBits);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoMacsCMac)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CMac_H