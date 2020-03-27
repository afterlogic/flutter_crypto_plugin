//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/util/Passphrase.java
//

#ifndef Passphrase_H
#define Passphrase_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSCharArray;

@interface LibComAfterlogicPgpUtilPassphrase : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithCharArray:(IOSCharArray *)chars;

- (void)clear;

+ (LibComAfterlogicPgpUtilPassphrase *)emptyPassphrase;

- (IOSCharArray *)getChars;

- (jboolean)isValid;

#pragma mark Protected

- (void)java_finalize;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibComAfterlogicPgpUtilPassphrase)

FOUNDATION_EXPORT void LibComAfterlogicPgpUtilPassphrase_initWithCharArray_(LibComAfterlogicPgpUtilPassphrase *self, IOSCharArray *chars);

FOUNDATION_EXPORT LibComAfterlogicPgpUtilPassphrase *new_LibComAfterlogicPgpUtilPassphrase_initWithCharArray_(IOSCharArray *chars) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpUtilPassphrase *create_LibComAfterlogicPgpUtilPassphrase_initWithCharArray_(IOSCharArray *chars);

FOUNDATION_EXPORT LibComAfterlogicPgpUtilPassphrase *LibComAfterlogicPgpUtilPassphrase_emptyPassphrase(void);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpUtilPassphrase)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Passphrase_H