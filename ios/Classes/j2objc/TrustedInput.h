//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/i18n/filter/TrustedInput.java
//

#ifndef TrustedInput_H
#define TrustedInput_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleI18nFilterTrustedInput : NSObject {
 @public
  id input_;
}

#pragma mark Public

- (instancetype __nonnull)initWithId:(id)input;

- (id)getInput;

- (NSString *)description;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleI18nFilterTrustedInput)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleI18nFilterTrustedInput, input_, id)

FOUNDATION_EXPORT void LibOrgBouncycastleI18nFilterTrustedInput_initWithId_(LibOrgBouncycastleI18nFilterTrustedInput *self, id input);

FOUNDATION_EXPORT LibOrgBouncycastleI18nFilterTrustedInput *new_LibOrgBouncycastleI18nFilterTrustedInput_initWithId_(id input) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleI18nFilterTrustedInput *create_LibOrgBouncycastleI18nFilterTrustedInput_initWithId_(id input);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleI18nFilterTrustedInput)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TrustedInput_H