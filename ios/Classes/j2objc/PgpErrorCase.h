//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/PgpErrorCase.java
//

#ifndef PgpErrorCase_H
#define PgpErrorCase_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/lang/Enum.h"

@class IOSObjectArray;

typedef NS_ENUM(NSUInteger, LibComAfterlogicPgpPgpErrorCase_Enum) {
  LibComAfterlogicPgpPgpErrorCase_Enum_Undefined = 0,
  LibComAfterlogicPgpPgpErrorCase_Enum_InvalidMessage = 1,
  LibComAfterlogicPgpPgpErrorCase_Enum_InvalidPassword = 2,
};

@interface LibComAfterlogicPgpPgpErrorCase : JavaLangEnum

@property (readonly, class, nonnull) LibComAfterlogicPgpPgpErrorCase *Undefined NS_SWIFT_NAME(Undefined);
@property (readonly, class, nonnull) LibComAfterlogicPgpPgpErrorCase *InvalidMessage NS_SWIFT_NAME(InvalidMessage);
@property (readonly, class, nonnull) LibComAfterlogicPgpPgpErrorCase *InvalidPassword NS_SWIFT_NAME(InvalidPassword);
+ (LibComAfterlogicPgpPgpErrorCase * __nonnull)Undefined;

+ (LibComAfterlogicPgpPgpErrorCase * __nonnull)InvalidMessage;

+ (LibComAfterlogicPgpPgpErrorCase * __nonnull)InvalidPassword;

#pragma mark Public

+ (LibComAfterlogicPgpPgpErrorCase *)valueOfWithNSString:(NSString *)name;

+ (IOSObjectArray *)values;

#pragma mark Package-Private

- (LibComAfterlogicPgpPgpErrorCase_Enum)toNSEnum;

@end

J2OBJC_STATIC_INIT(LibComAfterlogicPgpPgpErrorCase)

/*! INTERNAL ONLY - Use enum accessors declared below. */
FOUNDATION_EXPORT LibComAfterlogicPgpPgpErrorCase *LibComAfterlogicPgpPgpErrorCase_values_[];

inline LibComAfterlogicPgpPgpErrorCase *LibComAfterlogicPgpPgpErrorCase_get_Undefined(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpPgpErrorCase, Undefined)

inline LibComAfterlogicPgpPgpErrorCase *LibComAfterlogicPgpPgpErrorCase_get_InvalidMessage(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpPgpErrorCase, InvalidMessage)

inline LibComAfterlogicPgpPgpErrorCase *LibComAfterlogicPgpPgpErrorCase_get_InvalidPassword(void);
J2OBJC_ENUM_CONSTANT(LibComAfterlogicPgpPgpErrorCase, InvalidPassword)

FOUNDATION_EXPORT IOSObjectArray *LibComAfterlogicPgpPgpErrorCase_values(void);

FOUNDATION_EXPORT LibComAfterlogicPgpPgpErrorCase *LibComAfterlogicPgpPgpErrorCase_valueOfWithNSString_(NSString *name);

FOUNDATION_EXPORT LibComAfterlogicPgpPgpErrorCase *LibComAfterlogicPgpPgpErrorCase_fromOrdinal(NSUInteger ordinal);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpPgpErrorCase)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PgpErrorCase_H
