//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/gpg/keybox/jcajce/JcaBlobVerifier.java
//

#ifndef JcaBlobVerifier_H
#define JcaBlobVerifier_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "BlobVerifier.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleJcajceUtilJcaJceHelper;

@interface LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier : NSObject < LibOrgBouncycastleGpgKeyboxBlobVerifier >

#pragma mark Public

- (jboolean)isMatchedWithByteArray:(IOSByteArray *)blobData
                     withByteArray:(IOSByteArray *)blobDigest;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleJcajceUtilJcaJceHelper:(id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)helper;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier)

FOUNDATION_EXPORT void LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier *self, id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper);

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier *new_LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier *create_LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier_initWithLibOrgBouncycastleJcajceUtilJcaJceHelper_(id<LibOrgBouncycastleJcajceUtilJcaJceHelper> helper);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleGpgKeyboxJcajceJcaBlobVerifier)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcaBlobVerifier_H