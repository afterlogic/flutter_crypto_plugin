//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/SerpentEngine.java
//

#ifndef SerpentEngine_H
#define SerpentEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "SerpentEngineBase.h"

@class IOSByteArray;
@class IOSIntArray;

@interface LibOrgBouncycastleCryptoEnginesSerpentEngine : LibOrgBouncycastleCryptoEnginesSerpentEngineBase

#pragma mark Public

- (instancetype __nonnull)init;

#pragma mark Protected

- (void)decryptBlockWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outOff;

- (void)encryptBlockWithByteArray:(IOSByteArray *)input
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)output
                          withInt:(jint)outOff;

- (IOSIntArray *)makeWorkingKeyWithByteArray:(IOSByteArray *)key;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesSerpentEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesSerpentEngine_init(LibOrgBouncycastleCryptoEnginesSerpentEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesSerpentEngine *new_LibOrgBouncycastleCryptoEnginesSerpentEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesSerpentEngine *create_LibOrgBouncycastleCryptoEnginesSerpentEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesSerpentEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SerpentEngine_H
