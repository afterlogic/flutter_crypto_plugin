//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/JcePKIXCRLUtil.java
//

#ifndef JcePKIXCRLUtil_H
#define JcePKIXCRLUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class JavaUtilDate;
@class LibOrgBouncycastleJcajcePKIXCRLStoreSelector;
@protocol JavaUtilList;
@protocol JavaUtilSet;

@interface LibOrgBouncycastleJceProviderJcePKIXCRLUtil : NSObject

#pragma mark Public

- (id<JavaUtilSet>)findCRLsWithLibOrgBouncycastleJcajcePKIXCRLStoreSelector:(LibOrgBouncycastleJcajcePKIXCRLStoreSelector *)crlselect
                                                           withJavaUtilDate:(JavaUtilDate *)validityDate
                                                           withJavaUtilList:(id<JavaUtilList>)certStores
                                                           withJavaUtilList:(id<JavaUtilList>)pkixCrlStores;

#pragma mark Package-Private

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleJceProviderJcePKIXCRLUtil)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderJcePKIXCRLUtil_init(LibOrgBouncycastleJceProviderJcePKIXCRLUtil *self);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJcePKIXCRLUtil *new_LibOrgBouncycastleJceProviderJcePKIXCRLUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderJcePKIXCRLUtil *create_LibOrgBouncycastleJceProviderJcePKIXCRLUtil_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderJcePKIXCRLUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // JcePKIXCRLUtil_H