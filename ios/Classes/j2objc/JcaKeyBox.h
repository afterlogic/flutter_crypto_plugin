//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/gpg/keybox/jcajce/JcaKeyBox.java
//

#ifndef JcaKeyBox_H
#define JcaKeyBox_H

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

@interface LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox : LibOrgBouncycastleGpgKeyboxKeyBox

#pragma mark Package-Private

- (instancetype __nonnull)initWithByteArray:(IOSByteArray *)encoding
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)fingerPrintCalculator
withLibOrgBouncycastleGpgKeyboxBlobVerifier:(id<LibOrgBouncycastleGpgKeyboxBlobVerifier>)verifier;

- (instancetype __nonnull)initWithJavaIoInputStream:(JavaIoInputStream *)input
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)fingerPrintCalculator
        withLibOrgBouncycastleGpgKeyboxBlobVerifier:(id<LibOrgBouncycastleGpgKeyboxBlobVerifier>)verifier;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox)

FOUNDATION_EXPORT void LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox *self, IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> verifier);

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox *new_LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> verifier) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox *create_LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> verifier);

FOUNDATION_EXPORT void LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox *self, JavaIoInputStream *input, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> verifier);

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox *new_LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(JavaIoInputStream *input, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> verifier) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox *create_LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(JavaIoInputStream *input, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> verifier);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleGpgKeyboxJcajceJcaKeyBox)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcaKeyBox_H
