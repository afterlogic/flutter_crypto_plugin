//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPKeyValidationException.java
//

#ifndef PGPKeyValidationException_H
#define PGPKeyValidationException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPException.h"

@class JavaLangException;

@interface LibOrgBouncycastleOpenpgpPGPKeyValidationException : LibOrgBouncycastleOpenpgpPGPException

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)message;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangException:(JavaLangException *)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPKeyValidationException)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPKeyValidationException_initWithNSString_(LibOrgBouncycastleOpenpgpPGPKeyValidationException *self, NSString *message);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPKeyValidationException *new_LibOrgBouncycastleOpenpgpPGPKeyValidationException_initWithNSString_(NSString *message) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPKeyValidationException *create_LibOrgBouncycastleOpenpgpPGPKeyValidationException_initWithNSString_(NSString *message);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPKeyValidationException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPKeyValidationException_H