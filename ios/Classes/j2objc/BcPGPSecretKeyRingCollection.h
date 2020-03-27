//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/bc/BcPGPSecretKeyRingCollection.java
//

#ifndef BcPGPSecretKeyRingCollection_H
#define BcPGPSecretKeyRingCollection_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPSecretKeyRingCollection.h"

@class IOSByteArray;
@class JavaIoInputStream;
@protocol JavaUtilCollection;
@protocol LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;

@interface LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection : LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection

#pragma mark Public

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encoding;

- (instancetype __nonnull)initWithJavaUtilCollection:(id<JavaUtilCollection>)collection;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)inArg;

#pragma mark Package-Private

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)arg0
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)arg0
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection_initWithByteArray_(LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection *self, IOSByteArray *encoding);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection *new_LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection_initWithByteArray_(IOSByteArray *encoding) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection *create_LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection_initWithByteArray_(IOSByteArray *encoding);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection_initWithJavaIoInputStream_(LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection *self, JavaIoInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection *new_LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection_initWithJavaIoInputStream_(JavaIoInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection *create_LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection_initWithJavaIoInputStream_(JavaIoInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection_initWithJavaUtilCollection_(LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection *self, id<JavaUtilCollection> collection);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection *new_LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection_initWithJavaUtilCollection_(id<JavaUtilCollection> collection) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection *create_LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection_initWithJavaUtilCollection_(id<JavaUtilCollection> collection);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpBcBcPGPSecretKeyRingCollection)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // BcPGPSecretKeyRingCollection_H
