//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/BlowfishEngine.java
//

#ifndef BlowfishEngine_H
#define BlowfishEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesBlowfishEngine : NSObject < LibOrgBouncycastleCryptoBlockCipher >

#pragma mark Public

- (instancetype __nonnull)init;

- (NSString *)getAlgorithmName;

- (jint)getBlockSize;

- (void)init__WithBoolean:(jboolean)encrypting
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoEnginesBlowfishEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesBlowfishEngine_init(LibOrgBouncycastleCryptoEnginesBlowfishEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesBlowfishEngine *new_LibOrgBouncycastleCryptoEnginesBlowfishEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesBlowfishEngine *create_LibOrgBouncycastleCryptoEnginesBlowfishEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesBlowfishEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BlowfishEngine_H
