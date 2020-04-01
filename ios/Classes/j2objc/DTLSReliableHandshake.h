//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/DTLSReliableHandshake.java
//

#ifndef DTLSReliableHandshake_H
#define DTLSReliableHandshake_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "java/io/ByteArrayOutputStream.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoTlsDTLSRecordLayer;
@class LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_Message;
@protocol LibOrgBouncycastleCryptoTlsTlsContext;
@protocol LibOrgBouncycastleCryptoTlsTlsHandshakeHash;

@interface LibOrgBouncycastleCryptoTlsDTLSReliableHandshake : NSObject

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                         withLibOrgBouncycastleCryptoTlsDTLSRecordLayer:(LibOrgBouncycastleCryptoTlsDTLSRecordLayer *)transport;

- (void)finish;

- (id<LibOrgBouncycastleCryptoTlsTlsHandshakeHash>)getHandshakeHash;

- (void)notifyHelloComplete;

- (id<LibOrgBouncycastleCryptoTlsTlsHandshakeHash>)prepareToFinish;

- (LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_Message *)receiveMessage;

- (IOSByteArray *)receiveMessageBodyWithShort:(jshort)msg_type;

- (void)resetHandshakeMessagesDigest;

- (void)sendMessageWithShort:(jshort)msg_type
               withByteArray:(IOSByteArray *)body;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsDTLSReliableHandshake)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsDTLSRecordLayer_(LibOrgBouncycastleCryptoTlsDTLSReliableHandshake *self, id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsDTLSRecordLayer *transport);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsDTLSReliableHandshake *new_LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsDTLSRecordLayer_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsDTLSRecordLayer *transport) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsDTLSReliableHandshake *create_LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoTlsDTLSRecordLayer_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, LibOrgBouncycastleCryptoTlsDTLSRecordLayer *transport);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsDTLSReliableHandshake)

@interface LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_Message : NSObject

#pragma mark Public

- (IOSByteArray *)getBody;

- (jint)getSeq;

- (jshort)getType;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_Message)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_Message)

@interface LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_RecordLayerBuffer : JavaIoByteArrayOutputStream

#pragma mark Package-Private

- (instancetype __nonnull)initWithInt:(jint)size;

- (void)sendToRecordLayerWithLibOrgBouncycastleCryptoTlsDTLSRecordLayer:(LibOrgBouncycastleCryptoTlsDTLSRecordLayer *)recordLayer;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_RecordLayerBuffer)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_RecordLayerBuffer_initWithInt_(LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_RecordLayerBuffer *self, jint size);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_RecordLayerBuffer *new_LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_RecordLayerBuffer_initWithInt_(jint size) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_RecordLayerBuffer *create_LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_RecordLayerBuffer_initWithInt_(jint size);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsDTLSReliableHandshake_RecordLayerBuffer)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // DTLSReliableHandshake_H