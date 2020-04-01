//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/bc/OpenPgpBcSHA1PGPDigestCalculator.java
//

#ifndef OpenPgpBcSHA1PGPDigestCalculator_H
#define OpenPgpBcSHA1PGPDigestCalculator_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPDigestCalculator.h"

@class IOSByteArray;
@class JavaIoOutputStream;

@interface LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator : NSObject < LibOrgBouncycastleOpenpgpOperatorPGPDigestCalculator >

#pragma mark Public

- (jint)getAlgorithm;

- (IOSByteArray *)getDigest;

- (JavaIoOutputStream *)getOutputStream;

- (void)reset;

#pragma mark Package-Private

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator_init(LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator *self);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator *new_LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator *create_LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpOperatorBcOpenPgpBcSHA1PGPDigestCalculator)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OpenPgpBcSHA1PGPDigestCalculator_H