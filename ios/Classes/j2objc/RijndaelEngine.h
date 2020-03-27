//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/engines/RijndaelEngine.java
//

#ifndef RijndaelEngine_H
#define RijndaelEngine_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlockCipher.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSObjectArray;
@protocol LibOrgBouncycastleCryptoCipherParameters;

@interface LibOrgBouncycastleCryptoEnginesRijndaelEngine : NSObject < LibOrgBouncycastleCryptoBlockCipher >
@property (class) IOSObjectArray *shifts0 NS_SWIFT_NAME(shifts0);
@property (class) IOSObjectArray *shifts1 NS_SWIFT_NAME(shifts1);

+ (IOSObjectArray *)shifts0;

+ (void)setShifts0:(IOSObjectArray *)value;

+ (IOSObjectArray *)shifts1;

+ (void)setShifts1:(IOSObjectArray *)value;

#pragma mark Public

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithInt:(jint)blockBits;

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

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoEnginesRijndaelEngine)

inline IOSObjectArray *LibOrgBouncycastleCryptoEnginesRijndaelEngine_get_shifts0(void);
inline IOSObjectArray *LibOrgBouncycastleCryptoEnginesRijndaelEngine_set_shifts0(IOSObjectArray *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleCryptoEnginesRijndaelEngine_shifts0;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEnginesRijndaelEngine, shifts0, IOSObjectArray *)

inline IOSObjectArray *LibOrgBouncycastleCryptoEnginesRijndaelEngine_get_shifts1(void);
inline IOSObjectArray *LibOrgBouncycastleCryptoEnginesRijndaelEngine_set_shifts1(IOSObjectArray *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleCryptoEnginesRijndaelEngine_shifts1;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleCryptoEnginesRijndaelEngine, shifts1, IOSObjectArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesRijndaelEngine_init(LibOrgBouncycastleCryptoEnginesRijndaelEngine *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRijndaelEngine *new_LibOrgBouncycastleCryptoEnginesRijndaelEngine_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRijndaelEngine *create_LibOrgBouncycastleCryptoEnginesRijndaelEngine_init(void);

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoEnginesRijndaelEngine_initWithInt_(LibOrgBouncycastleCryptoEnginesRijndaelEngine *self, jint blockBits);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRijndaelEngine *new_LibOrgBouncycastleCryptoEnginesRijndaelEngine_initWithInt_(jint blockBits) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoEnginesRijndaelEngine *create_LibOrgBouncycastleCryptoEnginesRijndaelEngine_initWithInt_(jint blockBits);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoEnginesRijndaelEngine)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RijndaelEngine_H
