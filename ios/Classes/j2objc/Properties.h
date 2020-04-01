//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/Properties.java
//

#ifndef Properties_H
#define Properties_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaMathBigInteger;
@protocol JavaUtilSet;

@interface LibOrgBouncycastleUtilProperties : NSObject

#pragma mark Public

+ (JavaMathBigInteger *)asBigIntegerWithNSString:(NSString *)propertyName;

+ (id<JavaUtilSet>)asKeySetWithNSString:(NSString *)propertyName;

+ (jboolean)isOverrideSetWithNSString:(NSString *)propertyName;

+ (jboolean)removeThreadOverrideWithNSString:(NSString *)propertyName;

+ (jboolean)setThreadOverrideWithNSString:(NSString *)propertyName
                              withBoolean:(jboolean)enable;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleUtilProperties)

FOUNDATION_EXPORT jboolean LibOrgBouncycastleUtilProperties_isOverrideSetWithNSString_(NSString *propertyName);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleUtilProperties_setThreadOverrideWithNSString_withBoolean_(NSString *propertyName, jboolean enable);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleUtilProperties_removeThreadOverrideWithNSString_(NSString *propertyName);

FOUNDATION_EXPORT JavaMathBigInteger *LibOrgBouncycastleUtilProperties_asBigIntegerWithNSString_(NSString *propertyName);

FOUNDATION_EXPORT id<JavaUtilSet> LibOrgBouncycastleUtilProperties_asKeySetWithNSString_(NSString *propertyName);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleUtilProperties)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // Properties_H