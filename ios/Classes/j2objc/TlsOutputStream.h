//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsOutputStream.java
//

#ifndef TlsOutputStream_H
#define TlsOutputStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/OutputStream.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoTlsTlsProtocol;

@interface LibOrgBouncycastleCryptoTlsTlsOutputStream : JavaIoOutputStream

#pragma mark Public

- (void)close;

- (void)flush;

- (void)writeWithByteArray:(IOSByteArray *)buf
                   withInt:(jint)offset
                   withInt:(jint)len;

- (void)writeWithInt:(jint)arg0;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsProtocol:(LibOrgBouncycastleCryptoTlsTlsProtocol *)handler;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsOutputStream)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsOutputStream_initWithLibOrgBouncycastleCryptoTlsTlsProtocol_(LibOrgBouncycastleCryptoTlsTlsOutputStream *self, LibOrgBouncycastleCryptoTlsTlsProtocol *handler);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsOutputStream *new_LibOrgBouncycastleCryptoTlsTlsOutputStream_initWithLibOrgBouncycastleCryptoTlsTlsProtocol_(LibOrgBouncycastleCryptoTlsTlsProtocol *handler) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsOutputStream *create_LibOrgBouncycastleCryptoTlsTlsOutputStream_initWithLibOrgBouncycastleCryptoTlsTlsProtocol_(LibOrgBouncycastleCryptoTlsTlsProtocol *handler);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsOutputStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TlsOutputStream_H
