//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/algorithm/KeyFlag.java
//

#ifndef KeyFlag_H
#define KeyFlag_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/lang/Enum.h"

@class IOSObjectArray;
@protocol JavaUtilList;

typedef NS_ENUM(NSUInteger, LibComAfterlogicPgpAlgorithmKeyFlag_Enum) {
  LibComAfterlogicPgpAlgorithmKeyFlag_Enum_CERTIFY_OTHER = 0,
  LibComAfterlogicPgpAlgorithmKeyFlag_Enum_SIGN_DATA = 1,
  LibComAfterlogicPgpAlgorithmKeyFlag_Enum_ENCRYPT_COMMS = 2,
  LibComAfterlogicPgpAlgorithmKeyFlag_Enum_ENCRYPT_STORAGE = 3,
  LibComAfterlogicPgpAlgorithmKeyFlag_Enum_SPLIT = 4,
  LibComAfterlogicPgpAlgorithmKeyFlag_Enum_AUTHENTICATION = 5,
  LibComAfterlogicPgpAlgorithmKeyFlag_Enum_SHARED = 6,
};

@interface LibComAfterlogicPgpAlgorithmKeyFlag : JavaLangEnum

@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmKeyFlag *CERTIFY_OTHER NS_SWIFT_NAME(CERTIFY_OTHER);
@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmKeyFlag *SIGN_DATA NS_SWIFT_NAME(SIGN_DATA);
@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmKeyFlag *ENCRYPT_COMMS NS_SWIFT_NAME(ENCRYPT_COMMS);
@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmKeyFlag *ENCRYPT_STORAGE NS_SWIFT_NAME(ENCRYPT_STORAGE);
@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmKeyFlag *SPLIT NS_SWIFT_NAME(SPLIT);
@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmKeyFlag *AUTHENTICATION NS_SWIFT_NAME(AUTHENTICATION);
@property (readonly, class, nonnull) LibComAfterlogicPgpAlgorithmKeyFlag *SHARED NS_SWIFT_NAME(SHARED);
+ (LibComAfterlogicPgpAlgorithmKeyFlag * __nonnull)CERTIFY_OTHER;

+ (LibComAfterlogicPgpAlgorithmKeyFlag * __nonnull)SIGN_DATA;

+ (LibComAfterlogicPgpAlgorithmKeyFlag * __nonnull)ENCRYPT_COMMS;

+ (LibComAfterlogicPgpAlgorithmKeyFlag * __nonnull)ENCRYPT_STORAGE;

+ (LibComAfterlogicPgpAlgorithmKeyFlag * __nonnull)SPLIT;

+ (LibComAfterlogicPgpAlgorithmKeyFlag * __nonnull)AUTHENTICATION;

+ (LibComAfterlogicPgpAlgorithmKeyFlag * __nonnull)SHARED;

#pragma mark Public

+ (id<JavaUtilList>)fromIntegerWithInt:(jint)bitmask;

- (jint)getFlag;

+ (LibComAfterlogicPgpAlgorithmKeyFlag *)valueOfWithNSString:(NSString *)name;

+ (IOSObjectArray *)values;

#pragma mark Package-Private

- (LibComAfterlogicPgpAlgorithmKeyFlag_Enum)toNSEnum;

@end

J2OBJC_STATIC_INIT(LibComAfterlogicPgpAlgorithmKeyFlag)

/*! INTERNAL ONLY - Use enum accessors declared below. */
FOUNDATION_EXPORT LibComAfterlogicPgpAlgorithmKeyFlag *LibComAfterlogicPgpAlgorithmKeyFlag_values_[];

inline LibComAfterlogicPgpAlgorithmKeyFlag *LibComAfterlogicPgpAlgorithmKeyFlag_get_CERTIFY_OTHER(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmKeyFlag, CERTIFY_OTHER)

inline LibComAfterlogicPgpAlgorithmKeyFlag *LibComAfterlogicPgpAlgorithmKeyFlag_get_SIGN_DATA(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmKeyFlag, SIGN_DATA)

inline LibComAfterlogicPgpAlgorithmKeyFlag *LibComAfterlogicPgpAlgorithmKeyFlag_get_ENCRYPT_COMMS(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmKeyFlag, ENCRYPT_COMMS)

inline LibComAfterlogicPgpAlgorithmKeyFlag *LibComAfterlogicPgpAlgorithmKeyFlag_get_ENCRYPT_STORAGE(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmKeyFlag, ENCRYPT_STORAGE)

inline LibComAfterlogicPgpAlgorithmKeyFlag *LibComAfterlogicPgpAlgorithmKeyFlag_get_SPLIT(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmKeyFlag, SPLIT)

inline LibComAfterlogicPgpAlgorithmKeyFlag *LibComAfterlogicPgpAlgorithmKeyFlag_get_AUTHENTICATION(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmKeyFlag, AUTHENTICATION)

inline LibComAfterlogicPgpAlgorithmKeyFlag *LibComAfterlogicPgpAlgorithmKeyFlag_get_SHARED(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpAlgorithmKeyFlag, SHARED)

FOUNDATION_EXPORT id<JavaUtilList> LibComAfterlogicPgpAlgorithmKeyFlag_fromIntegerWithInt_(jint bitmask);

FOUNDATION_EXPORT IOSObjectArray *LibComAfterlogicPgpAlgorithmKeyFlag_values(void);

FOUNDATION_EXPORT LibComAfterlogicPgpAlgorithmKeyFlag *LibComAfterlogicPgpAlgorithmKeyFlag_valueOfWithNSString_(NSString *name);

FOUNDATION_EXPORT LibComAfterlogicPgpAlgorithmKeyFlag *LibComAfterlogicPgpAlgorithmKeyFlag_fromOrdinal(NSUInteger ordinal);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpAlgorithmKeyFlag)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyFlag_H
