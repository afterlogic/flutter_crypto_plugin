//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/jcajce/JcaPGPPublicKeyRing.java
//

#ifndef JcaPGPPublicKeyRing_H
#define JcaPGPPublicKeyRing_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPPublicKeyRing.h"

@class IOSByteArray;
@class JavaIoInputStream;
@protocol JavaUtilList;
@protocol LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;

@interface LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing : LibOrgBouncycastleOpenpgpPGPPublicKeyRing

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encoding;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)inArg;

#pragma mark Package-Private

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)arg0
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)arg0
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaUtilList:(id<JavaUtilList>)arg0 NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing_initWithByteArray_(LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing *self, IOSByteArray *encoding);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing *new_LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing_initWithByteArray_(IOSByteArray *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing *create_LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing_initWithByteArray_(IOSByteArray *encoding);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing_initWithJavaIoInputStream_(LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing *self, JavaIoInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing *new_LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing_initWithJavaIoInputStream_(JavaIoInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing *create_LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing_initWithJavaIoInputStream_(JavaIoInputStream *inArg);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpJcajceJcaPGPPublicKeyRing)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcaPGPPublicKeyRing_H