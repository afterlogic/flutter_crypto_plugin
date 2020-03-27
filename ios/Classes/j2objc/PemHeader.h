//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/io/pem/PemHeader.java
//

#ifndef PemHeader_H
#define PemHeader_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleUtilIoPemPemHeader : NSObject

#pragma mark Public

- (instancetype __nonnull)initWithNSString:(NSString *)name
                              withNSString:(NSString *)value;

- (jboolean)isEqual:(id)o;

- (NSString *)getName;

- (NSString *)getValue;

- (NSUInteger)hash;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilIoPemPemHeader)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilIoPemPemHeader_initWithNSString_withNSString_(LibOrgBouncycastleUtilIoPemPemHeader *self, NSString *name, NSString *value);

FOUNDATION_EXPORT LibOrgBouncycastleUtilIoPemPemHeader *new_LibOrgBouncycastleUtilIoPemPemHeader_initWithNSString_withNSString_(NSString *name, NSString *value) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilIoPemPemHeader *create_LibOrgBouncycastleUtilIoPemPemHeader_initWithNSString_withNSString_(NSString *name, NSString *value);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilIoPemPemHeader)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PemHeader_H