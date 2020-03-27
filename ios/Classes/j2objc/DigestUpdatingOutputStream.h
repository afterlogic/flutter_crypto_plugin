//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/io/DigestUpdatingOutputStream.java
//

#ifndef DigestUpdatingOutputStream_H
#define DigestUpdatingOutputStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/OutputStream.h"

@class IOSByteArray;
@class JavaSecurityMessageDigest;

@interface LibOrgBouncycastleJcajceIoDigestUpdatingOutputStream : JavaIoOutputStream

#pragma mark Public

- (void)writeWithByteArray:(IOSByteArray *)bytes;

- (void)writeWithByteArray:(IOSByteArray *)bytes
                   withInt:(jint)off
                   withInt:(jint)len;

- (void)writeWithInt:(jint)b;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaSecurityMessageDigest:(JavaSecurityMessageDigest *)digest;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceIoDigestUpdatingOutputStream)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceIoDigestUpdatingOutputStream_initWithJavaSecurityMessageDigest_(LibOrgBouncycastleJcajceIoDigestUpdatingOutputStream *self, JavaSecurityMessageDigest *digest);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceIoDigestUpdatingOutputStream *new_LibOrgBouncycastleJcajceIoDigestUpdatingOutputStream_initWithJavaSecurityMessageDigest_(JavaSecurityMessageDigest *digest) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceIoDigestUpdatingOutputStream *create_LibOrgBouncycastleJcajceIoDigestUpdatingOutputStream_initWithJavaSecurityMessageDigest_(JavaSecurityMessageDigest *digest);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceIoDigestUpdatingOutputStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DigestUpdatingOutputStream_H
