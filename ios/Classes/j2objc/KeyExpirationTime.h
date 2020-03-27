//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/sig/KeyExpirationTime.java
//

#ifndef KeyExpirationTime_H
#define KeyExpirationTime_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "SignatureSubpacket.h"

@class IOSByteArray;

@interface LibOrgBouncycastleBcpgSigKeyExpirationTime : LibOrgBouncycastleBcpgSignatureSubpacket

#pragma mark Public

- (instancetype __nonnull)initWithBoolean:(jboolean)critical
                              withBoolean:(jboolean)isLongLength
                            withByteArray:(IOSByteArray *)data;

- (instancetype __nonnull)initWithBoolean:(jboolean)critical
                                 withLong:(jlong)seconds;

- (jlong)getTime;

#pragma mark Protected

+ (IOSByteArray *)timeToBytesWithLong:(jlong)t;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0
                          withBoolean:(jboolean)arg1
                          withBoolean:(jboolean)arg2
                        withByteArray:(IOSByteArray *)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgSigKeyExpirationTime)

FOUNDATION_EXPORT IOSByteArray *LibOrgBouncycastleBcpgSigKeyExpirationTime_timeToBytesWithLong_(jlong t);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withBoolean_withByteArray_(LibOrgBouncycastleBcpgSigKeyExpirationTime *self, jboolean critical, jboolean isLongLength, IOSByteArray *data);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigKeyExpirationTime *new_LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigKeyExpirationTime *create_LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withBoolean_withByteArray_(jboolean critical, jboolean isLongLength, IOSByteArray *data);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withLong_(LibOrgBouncycastleBcpgSigKeyExpirationTime *self, jboolean critical, jlong seconds);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigKeyExpirationTime *new_LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withLong_(jboolean critical, jlong seconds) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSigKeyExpirationTime *create_LibOrgBouncycastleBcpgSigKeyExpirationTime_initWithBoolean_withLong_(jboolean critical, jlong seconds);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgSigKeyExpirationTime)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyExpirationTime_H
