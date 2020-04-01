//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/platform_stream/PlatformInputStream.java
//

#ifndef PlatformInputStream_H
#define PlatformInputStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/InputStream.h"

@class IOSByteArray;
@class LibComAfterlogicPgpPlatform_streamStreamCallback;

@interface LibComAfterlogicPgpPlatform_streamPlatformInputStream : JavaIoInputStream

#pragma mark Public

- (instancetype __nonnull)initWithLibComAfterlogicPgpPlatform_streamStreamCallback:(LibComAfterlogicPgpPlatform_streamStreamCallback *)endBufferCallback;

- (void)addBufferWithByteArray:(IOSByteArray *)buffer;

- (void)close;

- (jint)read;

- (jint)readWithByteArray:(IOSByteArray *)b
                  withInt:(jint)off
                  withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpPlatform_streamPlatformInputStream)

FOUNDATION_EXPORT void LibComAfterlogicPgpPlatform_streamPlatformInputStream_initWithLibComAfterlogicPgpPlatform_streamStreamCallback_(LibComAfterlogicPgpPlatform_streamPlatformInputStream *self, LibComAfterlogicPgpPlatform_streamStreamCallback *endBufferCallback);

FOUNDATION_EXPORT LibComAfterlogicPgpPlatform_streamPlatformInputStream *new_LibComAfterlogicPgpPlatform_streamPlatformInputStream_initWithLibComAfterlogicPgpPlatform_streamStreamCallback_(LibComAfterlogicPgpPlatform_streamStreamCallback *endBufferCallback) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpPlatform_streamPlatformInputStream *create_LibComAfterlogicPgpPlatform_streamPlatformInputStream_initWithLibComAfterlogicPgpPlatform_streamStreamCallback_(LibComAfterlogicPgpPlatform_streamStreamCallback *endBufferCallback);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpPlatform_streamPlatformInputStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PlatformInputStream_H