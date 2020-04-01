//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/KXTSBlockCipher.java
//

#ifndef KXTSBlockCipher_H
#define KXTSBlockCipher_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BufferedBlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoModesKXTSBlockCipher : LibOrgBouncycastleCryptoBufferedBlockCipher

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher;

- (jint)doFinalWithByteArray:(IOSByteArray *)output
                     withInt:(jint)outOff;

- (jint)getOutputSizeWithInt:(jint)length;

- (jint)getUpdateOutputSizeWithInt:(jint)len;

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters OBJC_METHOD_FAMILY_NONE;

- (jint)processByteWithByte:(jbyte)inArg
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff;

- (jint)processBytesWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outOff;

- (void)reset;

#pragma mark Protected

+ (jlong)getReductionPolynomialWithInt:(jint)blockSize;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesKXTSBlockCipher)

FOUNDATION_EXPORT jlong LibOrgBouncycastleCryptoModesKXTSBlockCipher_getReductionPolynomialWithInt_(jint blockSize);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesKXTSBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesKXTSBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> cipher);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesKXTSBlockCipher *new_LibOrgBouncycastleCryptoModesKXTSBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesKXTSBlockCipher *create_LibOrgBouncycastleCryptoModesKXTSBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesKXTSBlockCipher)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KXTSBlockCipher_H