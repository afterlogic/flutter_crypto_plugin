//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/G3413CBCBlockCipher.java
//

#ifndef G3413CBCBlockCipher_H
#define G3413CBCBlockCipher_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoModesG3413CBCBlockCipher : NSObject < LibOrgBouncycastleCryptoBlockCipher >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher;

- (NSString *)getAlgorithmName;

- (jint)getBlockSize;

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesG3413CBCBlockCipher)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesG3413CBCBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesG3413CBCBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> cipher);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesG3413CBCBlockCipher *new_LibOrgBouncycastleCryptoModesG3413CBCBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesG3413CBCBlockCipher *create_LibOrgBouncycastleCryptoModesG3413CBCBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesG3413CBCBlockCipher)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // G3413CBCBlockCipher_H
