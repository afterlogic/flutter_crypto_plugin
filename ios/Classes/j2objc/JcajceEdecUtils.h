//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/edec/JcajceEdecUtils.java
//

#ifndef JcajceEdecUtils_H
#define JcajceEdecUtils_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter;

@interface LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils : NSObject

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (jboolean)isValidPrefixWithByteArray:(IOSByteArray *)prefix
                         withByteArray:(IOSByteArray *)encoding;

+ (NSString *)keyToStringWithNSString:(NSString *)label
                         withNSString:(NSString *)algorithm
withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter:(LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *)pubKey;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils)

FOUNDATION_EXPORT void LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils_init(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils *self);

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils *new_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils *create_LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils_init(void);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils_isValidPrefixWithByteArray_withByteArray_(IOSByteArray *prefix, IOSByteArray *encoding);

FOUNDATION_EXPORT NSString *LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils_keyToStringWithNSString_withNSString_withLibOrgBouncycastleCryptoParamsAsymmetricKeyParameter_(NSString *label, NSString *algorithm, LibOrgBouncycastleCryptoParamsAsymmetricKeyParameter *pubKey);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJcajceProviderAsymmetricEdecJcajceEdecUtils)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcajceEdecUtils_H
