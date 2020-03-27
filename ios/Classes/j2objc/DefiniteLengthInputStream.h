//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DefiniteLengthInputStream.java
//

#ifndef DefiniteLengthInputStream_H
#define DefiniteLengthInputStream_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "LimitedInputStream.h"

@class IOSByteArray;
@class JavaIoInputStream;

@interface LibOrgBouncycastleAsn1DefiniteLengthInputStream : LibOrgBouncycastleAsn1LimitedInputStream

#pragma mark Public

- (jint)read;

- (jint)readWithByteArray:(IOSByteArray *)buf
                  withInt:(jint)off
                  withInt:(jint)len;

#pragma mark Package-Private

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
                                            withInt:(jint)length;

- (jint)getRemaining;

- (IOSByteArray *)toByteArray;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1DefiniteLengthInputStream)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DefiniteLengthInputStream_initWithJavaIoInputStream_withInt_(LibOrgBouncycastleAsn1DefiniteLengthInputStream *self, JavaIoInputStream *inArg, jint length);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DefiniteLengthInputStream *new_LibOrgBouncycastleAsn1DefiniteLengthInputStream_initWithJavaIoInputStream_withInt_(JavaIoInputStream *inArg, jint length) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DefiniteLengthInputStream *create_LibOrgBouncycastleAsn1DefiniteLengthInputStream_initWithJavaIoInputStream_withInt_(JavaIoInputStream *inArg, jint length);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DefiniteLengthInputStream)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DefiniteLengthInputStream_H
