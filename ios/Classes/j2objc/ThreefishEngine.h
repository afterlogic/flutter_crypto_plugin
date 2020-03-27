//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/ThreefishEngine.java
//

#ifndef ThreefishEngine_H
#define ThreefishEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSLongArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesThreefishEngine : NSObject < LibOrgBouncycastleCryptoBlockCipher >
@property (readonly, class) jint BLOCKSIZE_256 NS_SWIFT_NAME(BLOCKSIZE_256);
@property (readonly, class) jint BLOCKSIZE_512 NS_SWIFT_NAME(BLOCKSIZE_512);
@property (readonly, class) jint BLOCKSIZE_1024 NS_SWIFT_NAME(BLOCKSIZE_1024);

+ (jint)BLOCKSIZE_256;

+ (jint)BLOCKSIZE_512;

+ (jint)BLOCKSIZE_1024;

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)blocksizeBits;

+ (jlong)bytesToWordWithByteArray:(IOSByteArray *)bytes
                          withInt:(jint)off;

- (NSString *)getAlgorithmName;

- (jint)getBlockSize;

- (void)init__WithBoolean:(jboolean)forEncryption
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params OBJC_METHOD_FAMILY_NONE;

- (void)init__WithBoolean:(jboolean)forEncryption
            withLongArray:(IOSLongArray *)key
            withLongArray:(IOSLongArray *)tweak OBJC_METHOD_FAMILY_NONE;

- (jint)processBlockWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff;

- (jint)processBlockWithLongArray:(IOSLongArray *)inArg
                    withLongArray:(IOSLongArray *)outArg;

- (void)reset;

+ (void)wordToBytesWithLong:(jlong)word
              withByteArray:(IOSByteArray *)bytes
                    withInt:(jint)off;

#pragma mark Package-Private

+ (jlong)rotlXorWithLong:(jlong)x
                 withInt:(jint)n
                withLong:(jlong)xor_;

+ (jlong)xorRotrWithLong:(jlong)x
                 withInt:(jint)n
                withLong:(jlong)xor_;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoEnginesThreefishEngine)

inline jint LibOrgBouncycastleCryptoEnginesThreefishEngine_get_BLOCKSIZE_256(void);
#define LibOrgBouncycastleCryptoEnginesThreefishEngine_BLOCKSIZE_256 256
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesThreefishEngine, BLOCKSIZE_256, jint)

inline jint LibOrgBouncycastleCryptoEnginesThreefishEngine_get_BLOCKSIZE_512(void);
#define LibOrgBouncycastleCryptoEnginesThreefishEngine_BLOCKSIZE_512 512
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesThreefishEngine, BLOCKSIZE_512, jint)

inline jint LibOrgBouncycastleCryptoEnginesThreefishEngine_get_BLOCKSIZE_1024(void);
#define LibOrgBouncycastleCryptoEnginesThreefishEngine_BLOCKSIZE_1024 1024
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoEnginesThreefishEngine, BLOCKSIZE_1024, jint)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesThreefishEngine_initWithInt_(LibOrgBouncycastleCryptoEnginesThreefishEngine *self, jint blocksizeBits);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesThreefishEngine *new_LibOrgBouncycastleCryptoEnginesThreefishEngine_initWithInt_(jint blocksizeBits) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesThreefishEngine *create_LibOrgBouncycastleCryptoEnginesThreefishEngine_initWithInt_(jint blocksizeBits);

FOUNDATION_EXPORT jlong LibOrgBouncycastleCryptoEnginesThreefishEngine_bytesToWordWithByteArray_withInt_(IOSByteArray *bytes, jint off);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesThreefishEngine_wordToBytesWithLong_withByteArray_withInt_(jlong word, IOSByteArray *bytes, jint off);

FOUNDATION_EXPORT jlong LibOrgBouncycastleCryptoEnginesThreefishEngine_rotlXorWithLong_withInt_withLong_(jlong x, jint n, jlong xor_);

FOUNDATION_EXPORT jlong LibOrgBouncycastleCryptoEnginesThreefishEngine_xorRotrWithLong_withInt_withLong_(jlong x, jint n, jlong xor_);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesThreefishEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ThreefishEngine_H
