//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/io/StreamOverflowException.java
//

#ifndef StreamOverflowException_H
#define StreamOverflowException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/IOException.h"

@class JavaLangThrowable;

@interface LibOrgBouncycastleUtilIoStreamOverflowException : JavaIoIOException

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)msg;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilIoStreamOverflowException)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilIoStreamOverflowException_initWithNSString_(LibOrgBouncycastleUtilIoStreamOverflowException *self, NSString *msg);

FOUNDATION_EXPORT LibOrgBouncycastleUtilIoStreamOverflowException *new_LibOrgBouncycastleUtilIoStreamOverflowException_initWithNSString_(NSString *msg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilIoStreamOverflowException *create_LibOrgBouncycastleUtilIoStreamOverflowException_initWithNSString_(NSString *msg);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilIoStreamOverflowException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // StreamOverflowException_H
