//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/bc/BcPGPObjectFactory.java
//

#ifndef BcPGPObjectFactory_H
#define BcPGPObjectFactory_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPObjectFactory.h"

@class IOSByteArray;
@class JavaIoInputStream;
@protocol LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;

@interface LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory : LibOrgBouncycastleOpenpgpPGPObjectFactory

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encoded;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)inArg;

#pragma mark Package-Private

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)arg0
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)arg0
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory_initWithByteArray_(LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory *self, IOSByteArray *encoded);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory *new_LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory_initWithByteArray_(IOSByteArray *encoded) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory *create_LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory_initWithByteArray_(IOSByteArray *encoded);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory_initWithJavaIoInputStream_(LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory *self, JavaIoInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory *new_LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory_initWithJavaIoInputStream_(JavaIoInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory *create_LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory_initWithJavaIoInputStream_(JavaIoInputStream *inArg);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpBcBcPGPObjectFactory)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BcPGPObjectFactory_H