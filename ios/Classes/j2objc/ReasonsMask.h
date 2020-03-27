//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/provider/ReasonsMask.java
//

#ifndef ReasonsMask_H
#define ReasonsMask_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleAsn1X509ReasonFlags;

@interface LibOrgBouncycastleJceProviderReasonsMask : NSObject
@property (readonly, class) LibOrgBouncycastleJceProviderReasonsMask *allReasons NS_SWIFT_NAME(allReasons);

+ (LibOrgBouncycastleJceProviderReasonsMask *)allReasons;

#pragma mark Package-Private

- (instancetype __nonnull)init;

- (instancetype __nonnull)initWithLibOrgBouncycastleAsn1X509ReasonFlags:(LibOrgBouncycastleAsn1X509ReasonFlags *)reasons;

- (void)addReasonsWithLibOrgBouncycastleJceProviderReasonsMask:(LibOrgBouncycastleJceProviderReasonsMask *)mask;

- (jint)getReasons;

- (jboolean)hasNewReasonsWithLibOrgBouncycastleJceProviderReasonsMask:(LibOrgBouncycastleJceProviderReasonsMask *)mask;

- (LibOrgBouncycastleJceProviderReasonsMask *)intersectWithLibOrgBouncycastleJceProviderReasonsMask:(LibOrgBouncycastleJceProviderReasonsMask *)mask;

- (jboolean)isAllReasons;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleJceProviderReasonsMask)

inline LibOrgBouncycastleJceProviderReasonsMask *LibOrgBouncycastleJceProviderReasonsMask_get_allReasons(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT LibOrgBouncycastleJceProviderReasonsMask *LibOrgBouncycastleJceProviderReasonsMask_allReasons;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleJceProviderReasonsMask, allReasons, LibOrgBouncycastleJceProviderReasonsMask *)

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderReasonsMask_initWithLibOrgBouncycastleAsn1X509ReasonFlags_(LibOrgBouncycastleJceProviderReasonsMask *self, LibOrgBouncycastleAsn1X509ReasonFlags *reasons);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderReasonsMask *new_LibOrgBouncycastleJceProviderReasonsMask_initWithLibOrgBouncycastleAsn1X509ReasonFlags_(LibOrgBouncycastleAsn1X509ReasonFlags *reasons) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderReasonsMask *create_LibOrgBouncycastleJceProviderReasonsMask_initWithLibOrgBouncycastleAsn1X509ReasonFlags_(LibOrgBouncycastleAsn1X509ReasonFlags *reasons);

FOUNDATION_EXPORT void LibOrgBouncycastleJceProviderReasonsMask_init(LibOrgBouncycastleJceProviderReasonsMask *self);

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderReasonsMask *new_LibOrgBouncycastleJceProviderReasonsMask_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleJceProviderReasonsMask *create_LibOrgBouncycastleJceProviderReasonsMask_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleJceProviderReasonsMask)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ReasonsMask_H