//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/OutputStreamPacket.java
//

#ifndef OutputStreamPacket_H
#define OutputStreamPacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class LibOrgBouncycastleBcpgBCPGOutputStream;

@interface LibOrgBouncycastleBcpgOutputStreamPacket : NSObject {
 @public
  LibOrgBouncycastleBcpgBCPGOutputStream *out_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg;

- (void)close;

- (LibOrgBouncycastleBcpgBCPGOutputStream *)open;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgOutputStreamPacket)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgOutputStreamPacket, out_, LibOrgBouncycastleBcpgBCPGOutputStream *)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgOutputStreamPacket_initWithLibOrgBouncycastleBcpgBCPGOutputStream_(LibOrgBouncycastleBcpgOutputStreamPacket *self, LibOrgBouncycastleBcpgBCPGOutputStream *outArg);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgOutputStreamPacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // OutputStreamPacket_H