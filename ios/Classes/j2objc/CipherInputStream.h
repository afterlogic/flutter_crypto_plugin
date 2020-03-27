//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/io/CipherInputStream.java
//

#ifndef CipherInputStream_H
#define CipherInputStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/FilterInputStream.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaxCryptoCipher;

@interface LibOrgBouncycastleJcajceIoCipherInputStream : JavaIoFilterInputStream

#pragma mark Public

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)input
                              withJavaxCryptoCipher:(JavaxCryptoCipher *)cipher;

- (jint)available;

- (void)close;

- (void)markWithInt:(jint)readlimit;

- (jboolean)markSupported;

- (jint)read;

- (jint)readWithByteArray:(IOSByteArray *)b
                  withInt:(jint)off
                  withInt:(jint)len;

- (void)reset;

- (jlong)skipWithLong:(jlong)n;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceIoCipherInputStream)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceIoCipherInputStream_initWithJavaIoInputStream_withJavaxCryptoCipher_(LibOrgBouncycastleJcajceIoCipherInputStream *self, JavaIoInputStream *input, JavaxCryptoCipher *cipher);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceIoCipherInputStream *new_LibOrgBouncycastleJcajceIoCipherInputStream_initWithJavaIoInputStream_withJavaxCryptoCipher_(JavaIoInputStream *input, JavaxCryptoCipher *cipher) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceIoCipherInputStream *create_LibOrgBouncycastleJcajceIoCipherInputStream_initWithJavaIoInputStream_withJavaxCryptoCipher_(JavaIoInputStream *input, JavaxCryptoCipher *cipher);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceIoCipherInputStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CipherInputStream_H
