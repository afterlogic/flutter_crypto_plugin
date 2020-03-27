//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/UserMappingType.java
//

#ifndef UserMappingType_H
#define UserMappingType_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleCryptoTlsUserMappingType : NSObject
@property (readonly, class) jshort upn_domain_hint NS_SWIFT_NAME(upn_domain_hint);

+ (jshort)upn_domain_hint;

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsUserMappingType)

inline jshort LibOrgBouncycastleCryptoTlsUserMappingType_get_upn_domain_hint(void);
#define LibOrgBouncycastleCryptoTlsUserMappingType_upn_domain_hint 64
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsUserMappingType, upn_domain_hint, jshort)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsUserMappingType_init(LibOrgBouncycastleCryptoTlsUserMappingType *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsUserMappingType *new_LibOrgBouncycastleCryptoTlsUserMappingType_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsUserMappingType *create_LibOrgBouncycastleCryptoTlsUserMappingType_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsUserMappingType)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // UserMappingType_H
