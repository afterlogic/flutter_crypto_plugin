//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/gpg/keybox/bc/BcKeyBox.java
//

#ifndef BcKeyBox_H
#define BcKeyBox_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "KeyBox.h"

@class IOSByteArray;
@class JavaIoInputStream;
@protocol LibOrgBouncycastleGpgKeyboxBlobVerifier;
@protocol LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;

@interface LibOrgBouncycastleGpgKeyboxBcBcKeyBox : LibOrgBouncycastleGpgKeyboxKeyBox

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encoding;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)input;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)arg0
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)arg1
withLibOrgBouncycastleGpgKeyboxBlobVerifier:(id<LibOrgBouncycastleGpgKeyboxBlobVerifier>)arg2 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)arg0
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)arg1
        withLibOrgBouncycastleGpgKeyboxBlobVerifier:(id<LibOrgBouncycastleGpgKeyboxBlobVerifier>)arg2 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleGpgKeyboxBcBcKeyBox)

FOUNDATION_EXPORT void LibOrgBouncycastleGpgKeyboxBcBcKeyBox_initWithByteArray_(LibOrgBouncycastleGpgKeyboxBcBcKeyBox *self, IOSByteArray *encoding);

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxBcBcKeyBox *new_LibOrgBouncycastleGpgKeyboxBcBcKeyBox_initWithByteArray_(IOSByteArray *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxBcBcKeyBox *create_LibOrgBouncycastleGpgKeyboxBcBcKeyBox_initWithByteArray_(IOSByteArray *encoding);

FOUNDATION_EXPORT void LibOrgBouncycastleGpgKeyboxBcBcKeyBox_initWithJavaIoInputStream_(LibOrgBouncycastleGpgKeyboxBcBcKeyBox *self, JavaIoInputStream *input);

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxBcBcKeyBox *new_LibOrgBouncycastleGpgKeyboxBcBcKeyBox_initWithJavaIoInputStream_(JavaIoInputStream *input) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxBcBcKeyBox *create_LibOrgBouncycastleGpgKeyboxBcBcKeyBox_initWithJavaIoInputStream_(JavaIoInputStream *input);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleGpgKeyboxBcBcKeyBox)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BcKeyBox_H