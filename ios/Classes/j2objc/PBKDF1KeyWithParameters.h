//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/PBKDF1KeyWithParameters.java
//

#ifndef PBKDF1KeyWithParameters_H
#define PBKDF1KeyWithParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PBKDF1Key.h"
#include "javax/crypto/interfaces/PBEKey.h"

@class IOSByteArray;
@class IOSCharArray;
@protocol LibOrgBouncycastleCryptoCharToByteConverter;

@interface LibOrgBouncycastleJcajcePBKDF1KeyWithParameters : LibOrgBouncycastleJcajcePBKDF1Key < JavaxCryptoInterfacesPBEKey >

#pragma mark Public

- (instancetype __nonnull)initWithCharArray:(IOSCharArray *)password
withLibOrgBouncycastleCryptoCharToByteConverter:(id<LibOrgBouncycastleCryptoCharToByteConverter>)converter
                              withByteArray:(IOSByteArray *)salt
                                    withInt:(jint)iterationCount;

- (jint)getIterationCount;

- (IOSByteArray *)getSalt;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithCharArray:(IOSCharArray *)arg0
withLibOrgBouncycastleCryptoCharToByteConverter:(id<LibOrgBouncycastleCryptoCharToByteConverter>)arg1 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajcePBKDF1KeyWithParameters)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajcePBKDF1KeyWithParameters_initWithCharArray_withLibOrgBouncycastleCryptoCharToByteConverter_withByteArray_withInt_(LibOrgBouncycastleJcajcePBKDF1KeyWithParameters *self, IOSCharArray *password, id<LibOrgBouncycastleCryptoCharToByteConverter> converter, IOSByteArray *salt, jint iterationCount);

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePBKDF1KeyWithParameters *new_LibOrgBouncycastleJcajcePBKDF1KeyWithParameters_initWithCharArray_withLibOrgBouncycastleCryptoCharToByteConverter_withByteArray_withInt_(IOSCharArray *password, id<LibOrgBouncycastleCryptoCharToByteConverter> converter, IOSByteArray *salt, jint iterationCount) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajcePBKDF1KeyWithParameters *create_LibOrgBouncycastleJcajcePBKDF1KeyWithParameters_initWithCharArray_withLibOrgBouncycastleCryptoCharToByteConverter_withByteArray_withInt_(IOSCharArray *password, id<LibOrgBouncycastleCryptoCharToByteConverter> converter, IOSByteArray *salt, jint iterationCount);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajcePBKDF1KeyWithParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PBKDF1KeyWithParameters_H
