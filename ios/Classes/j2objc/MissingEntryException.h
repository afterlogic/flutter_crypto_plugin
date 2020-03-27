//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/i18n/MissingEntryException.java
//

#ifndef MissingEntryException_H
#define MissingEntryException_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/lang/RuntimeException.h"

@class JavaLangClassLoader;
@class JavaLangThrowable;
@class JavaUtilLocale;

@interface LibOrgBouncycastleI18nMissingEntryException : JavaLangRuntimeException {
 @public
  NSString *resource_;
  NSString *key_;
  JavaLangClassLoader *loader_;
  JavaUtilLocale *locale_;
}

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)message
                              withNSString:(NSString *)resource
                              withNSString:(NSString *)key
                        withJavaUtilLocale:(JavaUtilLocale *)locale
                   withJavaLangClassLoader:(JavaLangClassLoader *)loader;

- (instancetype __nonnull)initWithNSString:(NSString *)message
                     withJavaLangThrowable:(JavaLangThrowable *)cause
                              withNSString:(NSString *)resource
                              withNSString:(NSString *)key
                        withJavaUtilLocale:(JavaUtilLocale *)locale
                   withJavaLangClassLoader:(JavaLangClassLoader *)loader;

- (JavaLangClassLoader *)getClassLoader;

- (NSString *)getDebugMsg;

- (NSString *)getKey;

- (JavaUtilLocale *)getLocale;

- (NSString *)getResource;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

- (instancetype __nonnull)initWithJavaLangThrowable:(JavaLangThrowable *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1 NS_UNAVAILABLE;

- (instancetype __nonnull)initWithNSString:(NSString *)arg0
                     withJavaLangThrowable:(JavaLangThrowable *)arg1
                               withBoolean:(jboolean)arg2
                               withBoolean:(jboolean)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleI18nMissingEntryException)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleI18nMissingEntryException, resource_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleI18nMissingEntryException, key_, NSString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleI18nMissingEntryException, loader_, JavaLangClassLoader *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleI18nMissingEntryException, locale_, JavaUtilLocale *)

FOUNDATION_EXPORT void LibOrgBouncycastleI18nMissingEntryException_initWithNSString_withNSString_withNSString_withJavaUtilLocale_withJavaLangClassLoader_(LibOrgBouncycastleI18nMissingEntryException *self, NSString *message, NSString *resource, NSString *key, JavaUtilLocale *locale, JavaLangClassLoader *loader);

FOUNDATION_EXPORT LibOrgBouncycastleI18nMissingEntryException *new_LibOrgBouncycastleI18nMissingEntryException_initWithNSString_withNSString_withNSString_withJavaUtilLocale_withJavaLangClassLoader_(NSString *message, NSString *resource, NSString *key, JavaUtilLocale *locale, JavaLangClassLoader *loader) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleI18nMissingEntryException *create_LibOrgBouncycastleI18nMissingEntryException_initWithNSString_withNSString_withNSString_withJavaUtilLocale_withJavaLangClassLoader_(NSString *message, NSString *resource, NSString *key, JavaUtilLocale *locale, JavaLangClassLoader *loader);

FOUNDATION_EXPORT void LibOrgBouncycastleI18nMissingEntryException_initWithNSString_withJavaLangThrowable_withNSString_withNSString_withJavaUtilLocale_withJavaLangClassLoader_(LibOrgBouncycastleI18nMissingEntryException *self, NSString *message, JavaLangThrowable *cause, NSString *resource, NSString *key, JavaUtilLocale *locale, JavaLangClassLoader *loader);

FOUNDATION_EXPORT LibOrgBouncycastleI18nMissingEntryException *new_LibOrgBouncycastleI18nMissingEntryException_initWithNSString_withJavaLangThrowable_withNSString_withNSString_withJavaUtilLocale_withJavaLangClassLoader_(NSString *message, JavaLangThrowable *cause, NSString *resource, NSString *key, JavaUtilLocale *locale, JavaLangClassLoader *loader) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleI18nMissingEntryException *create_LibOrgBouncycastleI18nMissingEntryException_initWithNSString_withJavaLangThrowable_withNSString_withNSString_withJavaUtilLocale_withJavaLangClassLoader_(NSString *message, JavaLangThrowable *cause, NSString *resource, NSString *key, JavaUtilLocale *locale, JavaLangClassLoader *loader);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleI18nMissingEntryException)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // MissingEntryException_H
