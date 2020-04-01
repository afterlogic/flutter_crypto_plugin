//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/ECPointFormat.java
//

#ifndef ECPointFormat_H
#define ECPointFormat_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleCryptoTlsECPointFormat : NSObject
@property (readonly, class) jshort uncompressed NS_SWIFT_NAME(uncompressed);
@property (readonly, class) jshort ansiX962_compressed_prime NS_SWIFT_NAME(ansiX962_compressed_prime);
@property (readonly, class) jshort ansiX962_compressed_char2 NS_SWIFT_NAME(ansiX962_compressed_char2);

+ (jshort)uncompressed;

+ (jshort)ansiX962_compressed_prime;

+ (jshort)ansiX962_compressed_char2;

#pragma mark Public

- (instancetype __nonnull)init;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsECPointFormat)

inline jshort LibOrgBouncycastleCryptoTlsECPointFormat_get_uncompressed(void);
#define LibOrgBouncycastleCryptoTlsECPointFormat_uncompressed 0
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsECPointFormat, uncompressed, jshort)

inline jshort LibOrgBouncycastleCryptoTlsECPointFormat_get_ansiX962_compressed_prime(void);
#define LibOrgBouncycastleCryptoTlsECPointFormat_ansiX962_compressed_prime 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsECPointFormat, ansiX962_compressed_prime, jshort)

inline jshort LibOrgBouncycastleCryptoTlsECPointFormat_get_ansiX962_compressed_char2(void);
#define LibOrgBouncycastleCryptoTlsECPointFormat_ansiX962_compressed_char2 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsECPointFormat, ansiX962_compressed_char2, jshort)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsECPointFormat_init(LibOrgBouncycastleCryptoTlsECPointFormat *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsECPointFormat *new_LibOrgBouncycastleCryptoTlsECPointFormat_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsECPointFormat *create_LibOrgBouncycastleCryptoTlsECPointFormat_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsECPointFormat)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ECPointFormat_H