//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/CamelliaEngine.java
//

#ifndef CamelliaEngine_H
#define CamelliaEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesCamelliaEngine : NSObject < LibOrgBouncycastleCryptoBlockCipher >

#pragma mark Public

- (instancetype __nonnull)init;

- (NSString *)getAlgorithmName;

- (jint)getBlockSize;

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (void)reset;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoEnginesCamelliaEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesCamelliaEngine_init(LibOrgBouncycastleCryptoEnginesCamelliaEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesCamelliaEngine *new_LibOrgBouncycastleCryptoEnginesCamelliaEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesCamelliaEngine *create_LibOrgBouncycastleCryptoEnginesCamelliaEngine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesCamelliaEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CamelliaEngine_H
