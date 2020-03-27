//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/G3413CTRBlockCipher.java
//

#ifndef G3413CTRBlockCipher_H
#define G3413CTRBlockCipher_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "StreamBlockCipher.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoModesG3413CTRBlockCipher : LibOrgBouncycastleCryptoStreamBlockCipher

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher;

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher
                                                              withInt:(jint)bitBlockSize;

- (NSString *)getAlgorithmName;

- (jint)getBlockSize;

- (void)init__WithBoolean:(jboolean)encrypting
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

#pragma mark Protected

- (jbyte)calculateByteWithByte:(jbyte)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesG3413CTRBlockCipher)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesG3413CTRBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesG3413CTRBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> cipher);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesG3413CTRBlockCipher *new_LibOrgBouncycastleCryptoModesG3413CTRBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesG3413CTRBlockCipher *create_LibOrgBouncycastleCryptoModesG3413CTRBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesG3413CTRBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(LibOrgBouncycastleCryptoModesG3413CTRBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> cipher, jint bitBlockSize);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesG3413CTRBlockCipher *new_LibOrgBouncycastleCryptoModesG3413CTRBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(id<LibOrgBouncycastleCryptoBlockCipher> cipher, jint bitBlockSize) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesG3413CTRBlockCipher *create_LibOrgBouncycastleCryptoModesG3413CTRBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_withInt_(id<LibOrgBouncycastleCryptoBlockCipher> cipher, jint bitBlockSize);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesG3413CTRBlockCipher)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // G3413CTRBlockCipher_H
