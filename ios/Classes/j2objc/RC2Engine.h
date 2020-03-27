//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/RC2Engine.java
//

#ifndef RC2Engine_H
#define RC2Engine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesRC2Engine : NSObject < LibOrgBouncycastleCryptoBlockCipher >

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

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoEnginesRC2Engine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesRC2Engine_init(LibOrgBouncycastleCryptoEnginesRC2Engine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRC2Engine *new_LibOrgBouncycastleCryptoEnginesRC2Engine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRC2Engine *create_LibOrgBouncycastleCryptoEnginesRC2Engine_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesRC2Engine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RC2Engine_H
