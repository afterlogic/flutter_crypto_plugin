//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/WTauNafPreCompInfo.java
//

#ifndef WTauNafPreCompInfo_H
#define WTauNafPreCompInfo_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PreCompInfo.h"

@class IOSObjectArray;

@interface LibOrgBouncycastleMathEcWTauNafPreCompInfo : NSObject < LibOrgBouncycastleMathEcPreCompInfo > {
 @public
  IOSObjectArray *preComp_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (IOSObjectArray *)getPreComp;

- (void)setPreCompWithLibOrgBouncycastleMathEcECPoint_AbstractF2mArray:(IOSObjectArray *)preComp;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcWTauNafPreCompInfo)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcWTauNafPreCompInfo, preComp_, IOSObjectArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleMathEcWTauNafPreCompInfo_init(LibOrgBouncycastleMathEcWTauNafPreCompInfo *self);

FOUNDATION_EXPORT LibOrgBouncycastleMathEcWTauNafPreCompInfo *new_LibOrgBouncycastleMathEcWTauNafPreCompInfo_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleMathEcWTauNafPreCompInfo *create_LibOrgBouncycastleMathEcWTauNafPreCompInfo_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleMathEcWTauNafPreCompInfo)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // WTauNafPreCompInfo_H