//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/PublicKeyPacket.java
//

#ifndef PublicKeyPacket_H
#define PublicKeyPacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ContainedPacket.h"
#include "J2ObjC_header.h"
#include "PublicKeyAlgorithmTags.h"

@class IOSByteArray;
@class JavaUtilDate;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgBCPGOutputStream;
@protocol LibOrgBouncycastleBcpgBCPGKey;

@interface LibOrgBouncycastleBcpgPublicKeyPacket : LibOrgBouncycastleBcpgContainedPacket < LibOrgBouncycastleBcpgPublicKeyAlgorithmTags >

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)algorithm
                     withJavaUtilDate:(JavaUtilDate *)time
    withLibOrgBouncycastleBcpgBCPGKey:(id<LibOrgBouncycastleBcpgBCPGKey>)key;

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg;

- (jint)getAlgorithm;

- (IOSByteArray *)getEncodedContents;

- (id<LibOrgBouncycastleBcpgBCPGKey>)getKey;

- (JavaUtilDate *)getTime;

- (jint)getValidDays;

- (jint)getVersion;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgPublicKeyPacket)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgPublicKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgPublicKeyPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgPublicKeyPacket *new_LibOrgBouncycastleBcpgPublicKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgPublicKeyPacket *create_LibOrgBouncycastleBcpgPublicKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgPublicKeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(LibOrgBouncycastleBcpgPublicKeyPacket *self, jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgPublicKeyPacket *new_LibOrgBouncycastleBcpgPublicKeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgPublicKeyPacket *create_LibOrgBouncycastleBcpgPublicKeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgPublicKeyPacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PublicKeyPacket_H
