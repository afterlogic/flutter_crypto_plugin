//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/Times.java
//

#ifndef Times_H
#define Times_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleUtilTimes : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (jlong)nanoTime;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleUtilTimes)

FOUNDATION_EXPORT void LibOrgBouncycastleUtilTimes_init(LibOrgBouncycastleUtilTimes *self);

FOUNDATION_EXPORT LibOrgBouncycastleUtilTimes *new_LibOrgBouncycastleUtilTimes_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleUtilTimes *create_LibOrgBouncycastleUtilTimes_init(void);

FOUNDATION_EXPORT jlong LibOrgBouncycastleUtilTimes_nanoTime(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilTimes)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Times_H
