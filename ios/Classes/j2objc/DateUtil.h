//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/DateUtil.java
//

#ifndef DateUtil_H
#define DateUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaUtilDate;
@class JavaUtilLocale;

@interface LibOrgBouncycastleAsn1DateUtil : NSObject
@property (class) JavaUtilLocale *EN_Locale NS_SWIFT_NAME(EN_Locale);

+ (JavaUtilLocale *)EN_Locale;

+ (void)setEN_Locale:(JavaUtilLocale *)value;

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (JavaUtilDate *)epochAdjustWithJavaUtilDate:(JavaUtilDate *)date;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleAsn1DateUtil)

inline JavaUtilLocale *LibOrgBouncycastleAsn1DateUtil_get_EN_Locale(void);
inline JavaUtilLocale *LibOrgBouncycastleAsn1DateUtil_set_EN_Locale(JavaUtilLocale *value);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT JavaUtilLocale *LibOrgBouncycastleAsn1DateUtil_EN_Locale;
J2OBJC_STATIC_FIELD_OBJ(LibOrgBouncycastleAsn1DateUtil, EN_Locale, JavaUtilLocale *)

FOUNDATION_EXPORT void LibOrgBouncycastleAsn1DateUtil_init(LibOrgBouncycastleAsn1DateUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DateUtil *new_LibOrgBouncycastleAsn1DateUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleAsn1DateUtil *create_LibOrgBouncycastleAsn1DateUtil_init(void);

FOUNDATION_EXPORT JavaUtilDate *LibOrgBouncycastleAsn1DateUtil_epochAdjustWithJavaUtilDate_(JavaUtilDate *date);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleAsn1DateUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DateUtil_H
