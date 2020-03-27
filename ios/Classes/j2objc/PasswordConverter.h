//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/PasswordConverter.java
//

#ifndef PasswordConverter_H
#define PasswordConverter_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "CharToByteConverter.h"
#include "J2ObjC_header.h"
#include "java/lang/Enum.h"

@class IOSObjectArray;

typedef NS_ENUM(NSUInteger, LibOrgBouncycastleCryptoPasswordConverter_Enum) {
  LibOrgBouncycastleCryptoPasswordConverter_Enum_ASCII = 0,
  LibOrgBouncycastleCryptoPasswordConverter_Enum_UTF8 = 1,
  LibOrgBouncycastleCryptoPasswordConverter_Enum_PKCS12 = 2,
};

@interface LibOrgBouncycastleCryptoPasswordConverter : JavaLangEnum < LibOrgBouncycastleCryptoCharToByteConverter >

@property (readonly, class, nonnull) LibOrgBouncycastleCryptoPasswordConverter *ASCII NS_SWIFT_NAME(ASCII);
@property (readonly, class, nonnull) LibOrgBouncycastleCryptoPasswordConverter *UTF8 NS_SWIFT_NAME(UTF8);
@property (readonly, class, nonnull) LibOrgBouncycastleCryptoPasswordConverter *PKCS12 NS_SWIFT_NAME(PKCS12);
+ (LibOrgBouncycastleCryptoPasswordConverter * __nonnull)ASCII;

+ (LibOrgBouncycastleCryptoPasswordConverter * __nonnull)UTF8;

+ (LibOrgBouncycastleCryptoPasswordConverter * __nonnull)PKCS12;

#pragma mark Public

+ (LibOrgBouncycastleCryptoPasswordConverter *)valueOfWithNSString:(NSString *)name;

+ (IOSObjectArray *)values;

#pragma mark Package-Private

- (LibOrgBouncycastleCryptoPasswordConverter_Enum)toNSEnum;

@end

J2OBJC_STATIC_INIT(LibOrgBouncycastleCryptoPasswordConverter)

/*! INTERNAL ONLY - Use enum accessors declared below. */
FOUNDATION_EXPORT LibOrgBouncycastleCryptoPasswordConverter *LibOrgBouncycastleCryptoPasswordConverter_values_[];

inline LibOrgBouncycastleCryptoPasswordConverter *LibOrgBouncycastleCryptoPasswordConverter_get_ASCII(void);
J2OBJC_ENUM_CONSTANT(LibOrgBouncycastleCryptoPasswordConverter, ASCII)

inline LibOrgBouncycastleCryptoPasswordConverter *LibOrgBouncycastleCryptoPasswordConverter_get_UTF8(void);
J2OBJC_ENUM_CONSTANT(LibOrgBouncycastleCryptoPasswordConverter, UTF8)

inline LibOrgBouncycastleCryptoPasswordConverter *LibOrgBouncycastleCryptoPasswordConverter_get_PKCS12(void);
J2OBJC_ENUM_CONSTANT(LibOrgBouncycastleCryptoPasswordConverter, PKCS12)

FOUNDATION_EXPORT IOSObjectArray *LibOrgBouncycastleCryptoPasswordConverter_values(void);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPasswordConverter *LibOrgBouncycastleCryptoPasswordConverter_valueOfWithNSString_(NSString *name);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoPasswordConverter *LibOrgBouncycastleCryptoPasswordConverter_fromOrdinal(NSUInteger ordinal);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoPasswordConverter)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PasswordConverter_H