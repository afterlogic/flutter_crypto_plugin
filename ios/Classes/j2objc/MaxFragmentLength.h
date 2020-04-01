//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/MaxFragmentLength.java
//

#ifndef MaxFragmentLength_H
#define MaxFragmentLength_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@interface LibOrgBouncycastleCryptoTlsMaxFragmentLength : NSObject
@property (readonly, class) jshort pow2_9 NS_SWIFT_NAME(pow2_9);
@property (readonly, class) jshort pow2_10 NS_SWIFT_NAME(pow2_10);
@property (readonly, class) jshort pow2_11 NS_SWIFT_NAME(pow2_11);
@property (readonly, class) jshort pow2_12 NS_SWIFT_NAME(pow2_12);

+ (jshort)pow2_9;

+ (jshort)pow2_10;

+ (jshort)pow2_11;

+ (jshort)pow2_12;

#pragma mark Public

- (instancetype __nonnull)init;

+ (jboolean)isValidWithShort:(jshort)maxFragmentLength;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsMaxFragmentLength)

inline jshort LibOrgBouncycastleCryptoTlsMaxFragmentLength_get_pow2_9(void);
#define LibOrgBouncycastleCryptoTlsMaxFragmentLength_pow2_9 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsMaxFragmentLength, pow2_9, jshort)

inline jshort LibOrgBouncycastleCryptoTlsMaxFragmentLength_get_pow2_10(void);
#define LibOrgBouncycastleCryptoTlsMaxFragmentLength_pow2_10 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsMaxFragmentLength, pow2_10, jshort)

inline jshort LibOrgBouncycastleCryptoTlsMaxFragmentLength_get_pow2_11(void);
#define LibOrgBouncycastleCryptoTlsMaxFragmentLength_pow2_11 3
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsMaxFragmentLength, pow2_11, jshort)

inline jshort LibOrgBouncycastleCryptoTlsMaxFragmentLength_get_pow2_12(void);
#define LibOrgBouncycastleCryptoTlsMaxFragmentLength_pow2_12 4
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleCryptoTlsMaxFragmentLength, pow2_12, jshort)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsMaxFragmentLength_init(LibOrgBouncycastleCryptoTlsMaxFragmentLength *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsMaxFragmentLength *new_LibOrgBouncycastleCryptoTlsMaxFragmentLength_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsMaxFragmentLength *create_LibOrgBouncycastleCryptoTlsMaxFragmentLength_init(void);

FOUNDATION_EXPORT jboolean LibOrgBouncycastleCryptoTlsMaxFragmentLength_isValidWithShort_(jshort maxFragmentLength);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsMaxFragmentLength)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // MaxFragmentLength_H