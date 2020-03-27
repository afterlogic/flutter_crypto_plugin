//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/CompressedDataPacket.java
//

#ifndef CompressedDataPacket_H
#define CompressedDataPacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "InputStreamPacket.h"
#include "J2ObjC_header.h"

@class LibOrgBouncycastleBcpgBCPGInputStream;

@interface LibOrgBouncycastleBcpgCompressedDataPacket : LibOrgBouncycastleBcpgInputStreamPacket {
 @public
  jint algorithm_;
}

#pragma mark Public

- (jint)getAlgorithm;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgCompressedDataPacket)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgCompressedDataPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgCompressedDataPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgCompressedDataPacket *new_LibOrgBouncycastleBcpgCompressedDataPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgCompressedDataPacket *create_LibOrgBouncycastleBcpgCompressedDataPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgCompressedDataPacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // CompressedDataPacket_H