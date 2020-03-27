//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/sig/RevocationReasonTags.java
//

#ifndef RevocationReasonTags_H
#define RevocationReasonTags_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@protocol LibOrgBouncycastleBcpgSigRevocationReasonTags < JavaObject >

@end

@interface LibOrgBouncycastleBcpgSigRevocationReasonTags : NSObject
@property (readonly, class) jbyte NO_REASON NS_SWIFT_NAME(NO_REASON);
@property (readonly, class) jbyte KEY_SUPERSEDED NS_SWIFT_NAME(KEY_SUPERSEDED);
@property (readonly, class) jbyte KEY_COMPROMISED NS_SWIFT_NAME(KEY_COMPROMISED);
@property (readonly, class) jbyte KEY_RETIRED NS_SWIFT_NAME(KEY_RETIRED);
@property (readonly, class) jbyte USER_NO_LONGER_VALID NS_SWIFT_NAME(USER_NO_LONGER_VALID);

+ (jbyte)NO_REASON;

+ (jbyte)KEY_SUPERSEDED;

+ (jbyte)KEY_COMPROMISED;

+ (jbyte)KEY_RETIRED;

+ (jbyte)USER_NO_LONGER_VALID;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgSigRevocationReasonTags)

inline jbyte LibOrgBouncycastleBcpgSigRevocationReasonTags_get_NO_REASON(void);
#define LibOrgBouncycastleBcpgSigRevocationReasonTags_NO_REASON 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSigRevocationReasonTags, NO_REASON, jbyte)

inline jbyte LibOrgBouncycastleBcpgSigRevocationReasonTags_get_KEY_SUPERSEDED(void);
#define LibOrgBouncycastleBcpgSigRevocationReasonTags_KEY_SUPERSEDED 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSigRevocationReasonTags, KEY_SUPERSEDED, jbyte)

inline jbyte LibOrgBouncycastleBcpgSigRevocationReasonTags_get_KEY_COMPROMISED(void);
#define LibOrgBouncycastleBcpgSigRevocationReasonTags_KEY_COMPROMISED 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSigRevocationReasonTags, KEY_COMPROMISED, jbyte)

inline jbyte LibOrgBouncycastleBcpgSigRevocationReasonTags_get_KEY_RETIRED(void);
#define LibOrgBouncycastleBcpgSigRevocationReasonTags_KEY_RETIRED 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSigRevocationReasonTags, KEY_RETIRED, jbyte)

inline jbyte LibOrgBouncycastleBcpgSigRevocationReasonTags_get_USER_NO_LONGER_VALID(void);
#define LibOrgBouncycastleBcpgSigRevocationReasonTags_USER_NO_LONGER_VALID 32
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleBcpgSigRevocationReasonTags, USER_NO_LONGER_VALID, jbyte)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgSigRevocationReasonTags)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // RevocationReasonTags_H