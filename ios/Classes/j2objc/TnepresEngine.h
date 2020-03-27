//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/TnepresEngine.java
//

#ifndef TnepresEngine_H
#define TnepresEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "SerpentEngineBase.h"

@class IOSByteArray;
@class IOSIntArray;

@interface LibOrgBouncycastleCryptoEnginesTnepresEngine : LibOrgBouncycastleCryptoEnginesSerpentEngineBase

#pragma mark Public

- (instancetype __nonnull)init;

- (NSString *)getAlgorithmName;

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

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesTnepresEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesTnepresEngine_init(LibOrgBouncycastleCryptoEnginesTnepresEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesTnepresEngine *new_LibOrgBouncycastleCryptoEnginesTnepresEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesTnepresEngine *create_LibOrgBouncycastleCryptoEnginesTnepresEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesTnepresEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TnepresEngine_H
