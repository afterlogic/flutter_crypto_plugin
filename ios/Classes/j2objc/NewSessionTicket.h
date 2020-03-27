//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/NewSessionTicket.java
//

#ifndef NewSessionTicket_H
#define NewSessionTicket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;

@interface LibOrgBouncycastleCryptoTlsNewSessionTicket : NSObject {
 @public
  jlong ticketLifetimeHint_;
  IOSByteArray *ticket_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLong:(jlong)ticketLifetimeHint
                         withByteArray:(IOSByteArray *)ticket;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (IOSByteArray *)getTicket;

- (jlong)getTicketLifetimeHint;

+ (LibOrgBouncycastleCryptoTlsNewSessionTicket *)parseWithJavaIoInputStream:(JavaIoInputStream *)input;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsNewSessionTicket)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsNewSessionTicket, ticket_, IOSByteArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsNewSessionTicket_initWithLong_withByteArray_(LibOrgBouncycastleCryptoTlsNewSessionTicket *self, jlong ticketLifetimeHint, IOSByteArray *ticket);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsNewSessionTicket *new_LibOrgBouncycastleCryptoTlsNewSessionTicket_initWithLong_withByteArray_(jlong ticketLifetimeHint, IOSByteArray *ticket) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsNewSessionTicket *create_LibOrgBouncycastleCryptoTlsNewSessionTicket_initWithLong_withByteArray_(jlong ticketLifetimeHint, IOSByteArray *ticket);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsNewSessionTicket *LibOrgBouncycastleCryptoTlsNewSessionTicket_parseWithJavaIoInputStream_(JavaIoInputStream *input);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsNewSessionTicket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NewSessionTicket_H
