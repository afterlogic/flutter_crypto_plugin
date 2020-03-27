//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/InputStreamPacket.java
//

#ifndef InputStreamPacket_H
#define InputStreamPacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "Packet.h"

@class LibOrgBouncycastleBcpgBCPGInputStream;

@interface LibOrgBouncycastleBcpgInputStreamPacket : LibOrgBouncycastleBcpgPacket

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

- (LibOrgBouncycastleBcpgBCPGInputStream *)getInputStream;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgInputStreamPacket)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgInputStreamPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgInputStreamPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgInputStreamPacket *new_LibOrgBouncycastleBcpgInputStreamPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgInputStreamPacket *create_LibOrgBouncycastleBcpgInputStreamPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgInputStreamPacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // InputStreamPacket_H