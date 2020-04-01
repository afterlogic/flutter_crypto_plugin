//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/RFC3211WrapEngine.java
//

#ifndef RFC3211WrapEngine_H
#define RFC3211WrapEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Wrapper.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesRFC3211WrapEngine : NSObject < LibOrgBouncycastleCryptoWrapper >

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)engine;

- (NSString *)getAlgorithmName;

- (void)init__WithBoolean:(jboolean)forWrapping
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param OBJC_METHOD_FAMILY_NONE;

- (IOSByteArray *)unwrapWithByteArray:(IOSByteArray *)inArg
                              withInt:(jint)inOff
                              withInt:(jint)inLen;

- (IOSByteArray *)wrapWithByteArray:(IOSByteArray *)inArg
                            withInt:(jint)inOff
                            withInt:(jint)inLen;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoEnginesRFC3211WrapEngine)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesRFC3211WrapEngine_initWithLibOrgBouncycastleCryptoBlockCipher_(LibOrgBouncycastleCryptoEnginesRFC3211WrapEngine *self, id<LibOrgBouncycastleCryptoBlockCipher> engine);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRFC3211WrapEngine *new_LibOrgBouncycastleCryptoEnginesRFC3211WrapEngine_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> engine) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRFC3211WrapEngine *create_LibOrgBouncycastleCryptoEnginesRFC3211WrapEngine_initWithLibOrgBouncycastleCryptoBlockCipher_(id<LibOrgBouncycastleCryptoBlockCipher> engine);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesRFC3211WrapEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RFC3211WrapEngine_H