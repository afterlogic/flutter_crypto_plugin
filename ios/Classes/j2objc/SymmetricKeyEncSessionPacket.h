//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/SymmetricKeyEncSessionPacket.java
//

#ifndef SymmetricKeyEncSessionPacket_H
#define SymmetricKeyEncSessionPacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ContainedPacket.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgBCPGOutputStream;
@class LibOrgBouncycastleBcpgS2K;

@interface LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket : LibOrgBouncycastleBcpgContainedPacket

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

- (instancetype __nonnull)initWithInt:(jint)encAlgorithm
        withLibOrgBouncycastleBcpgS2K:(LibOrgBouncycastleBcpgS2K *)s2k
                        withByteArray:(IOSByteArray *)secKeyData;

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg;

- (jint)getEncAlgorithm;

- (LibOrgBouncycastleBcpgS2K *)getS2K;

- (IOSByteArray *)getSecKeyData;

- (jint)getVersion;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket *new_LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket *create_LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket_initWithInt_withLibOrgBouncycastleBcpgS2K_withByteArray_(LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket *self, jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *secKeyData);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket *new_LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket_initWithInt_withLibOrgBouncycastleBcpgS2K_withByteArray_(jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *secKeyData) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket *create_LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket_initWithInt_withLibOrgBouncycastleBcpgS2K_withByteArray_(jint encAlgorithm, LibOrgBouncycastleBcpgS2K *s2k, IOSByteArray *secKeyData);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgSymmetricKeyEncSessionPacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SymmetricKeyEncSessionPacket_H