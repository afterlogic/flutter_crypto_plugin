//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/sphincs/Permute.java
//

#ifndef Permute_H
#define Permute_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSIntArray;

@interface LibOrgBouncycastlePqcCryptoSphincsPermute : NSObject

#pragma mark Public

+ (void)permuteWithInt:(jint)rounds
          withIntArray:(IOSIntArray *)x;

#pragma mark Protected

+ (jint)rotlWithInt:(jint)x
            withInt:(jint)y;

#pragma mark Package-Private

- (instancetype __nonnull)init;

- (void)chacha_permuteWithByteArray:(IOSByteArray *)outArg
                      withByteArray:(IOSByteArray *)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastlePqcCryptoSphincsPermute)

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoSphincsPermute_init(LibOrgBouncycastlePqcCryptoSphincsPermute *self);

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoSphincsPermute *new_LibOrgBouncycastlePqcCryptoSphincsPermute_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastlePqcCryptoSphincsPermute *create_LibOrgBouncycastlePqcCryptoSphincsPermute_init(void);

FOUNDATION_EXPORT jint LibOrgBouncycastlePqcCryptoSphincsPermute_rotlWithInt_withInt_(jint x, jint y);

FOUNDATION_EXPORT void LibOrgBouncycastlePqcCryptoSphincsPermute_permuteWithInt_withIntArray_(jint rounds, IOSIntArray *x);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastlePqcCryptoSphincsPermute)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Permute_H
