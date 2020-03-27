//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/CertChainType.java
//

#ifndef CertChainType_H
#define CertChainType_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleCryptoTlsCertChainType : NSObject
@property (readonly, class) jshort individual_certs NS_SWIFT_NAME(individual_certs);
@property (readonly, class) jshort pkipath NS_SWIFT_NAME(pkipath);

+ (jshort)individual_certs;

+ (jshort)pkipath;

#pragma mark Public

- (instancetype __nonnull)init;

+ (jboolean)isValidWithShort:(jshort)certChainType;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsCertChainType)

inline jshort LibOrgBouncycastleCryptoTlsCertChainType_get_individual_certs(void);
#define LibOrgBouncycastleCryptoTlsCertChainType_individual_certs 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsCertChainType, individual_certs, jshort)

inline jshort LibOrgBouncycastleCryptoTlsCertChainType_get_pkipath(void);
#define LibOrgBouncycastleCryptoTlsCertChainType_pkipath 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsCertChainType, pkipath, jshort)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsCertChainType_init(LibOrgBouncycastleCryptoTlsCertChainType *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsCertChainType *new_LibOrgBouncycastleCryptoTlsCertChainType_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsCertChainType *create_LibOrgBouncycastleCryptoTlsCertChainType_init(void);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleCryptoTlsCertChainType_isValidWithShort_(jshort certChainType);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsCertChainType)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CertChainType_H