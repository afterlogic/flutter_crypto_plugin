//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/generators/KDF1BytesGenerator.java
//

#ifndef KDF1BytesGenerator_H
#define KDF1BytesGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BaseKDFBytesGenerator.h"
#include "J2ObjC_header.h"

@protocol LibOrgBouncycastleCryptoDigest;

@interface LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator : LibOrgBouncycastleCryptoGeneratorsBaseKDFBytesGenerator

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)digest;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0
   withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator *self, id<LibOrgBouncycastleCryptoDigest> digest);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator *new_LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator *create_LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator_initWithLibOrgBouncycastleCryptoDigest_(id<LibOrgBouncycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoGeneratorsKDF1BytesGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KDF1BytesGenerator_H
