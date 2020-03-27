//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/modes/CTSBlockCipher.java
//

#ifndef CTSBlockCipher_H
#define CTSBlockCipher_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BufferedBlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoBlockCipher;

@interface LibOrgBouncycastleCryptoModesCTSBlockCipher : LibOrgBouncycastleCryptoBufferedBlockCipher

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)cipher;

- (jint)doFinalWithByteArray:(IOSByteArray *)outArg
                     withInt:(jint)outOff;

- (jint)getOutputSizeWithInt:(jint)len;

- (jint)getUpdateOutputSizeWithInt:(jint)len;

- (jint)processByteWithByte:(jbyte)inArg
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff;

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoModesCTSBlockCipher)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoModesCTSBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoModesCTSBlockCipher *self, id<LibOrgBouncycastleCryptoBlockCipher> cipher);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesCTSBlockCipher *new_LibOrgBouncycastleCryptoModesCTSBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoModesCTSBlockCipher *create_LibOrgBouncycastleCryptoModesCTSBlockCipher_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> cipher);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoModesCTSBlockCipher)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CTSBlockCipher_H