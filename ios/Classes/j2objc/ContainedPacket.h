//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/ContainedPacket.java
//

#ifndef ContainedPacket_H
#define ContainedPacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "Encodable.h"
#include "J2ObjC_header.h"
#include "Packet.h"

@class IOSByteArray;
@class LibOrgBouncycastleBcpgBCPGOutputStream;

@interface LibOrgBouncycastleBcpgContainedPacket : LibOrgBouncycastleBcpgPacket < LibOrgBouncycastleUtilEncodable >

#pragma mark Public

- (instancetype __nonnull)init;

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)pOut;

- (IOSByteArray *)getEncoded;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgContainedPacket)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgContainedPacket_init(LibOrgBouncycastleBcpgContainedPacket *self);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgContainedPacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // ContainedPacket_H