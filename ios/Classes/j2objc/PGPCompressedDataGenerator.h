//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPCompressedDataGenerator.java
//

#ifndef PGPCompressedDataGenerator_H
#define PGPCompressedDataGenerator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CompressionAlgorithmTags.h"
#include "J2ObjC_header.h"
#include "StreamGenerator.h"

@class IOSByteArray;
@class JavaIoOutputStream;

@interface LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator : NSObject < LibOrgBouncycastleBcpgCompressionAlgorithmTags, LibOrgBouncycastleOpenpgpStreamGenerator >

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)algorithm;

- (instancetype __nonnull)initWithInt:(jint)algorithm
                              withInt:(jint)compression;

- (void)close;

- (JavaIoOutputStream *)openWithJavaIoOutputStream:(JavaIoOutputStream *)outArg;

- (JavaIoOutputStream *)openWithJavaIoOutputStream:(JavaIoOutputStream *)outArg
                                     withByteArray:(IOSByteArray *)buffer;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *self, jint algorithm);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_(jint algorithm) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *create_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_(jint algorithm);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_withInt_(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *self, jint algorithm, jint compression);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *new_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_withInt_(jint algorithm, jint compression) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator *create_LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator_initWithInt_withInt_(jint algorithm, jint compression);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPCompressedDataGenerator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPCompressedDataGenerator_H
