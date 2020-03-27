//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsStreamCipher.java
//

#ifndef TlsStreamCipher_H
#define TlsStreamCipher_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "TlsCipher.h"

@class IOSByteArray;
@class LibOrgBouncycastleCryptoTlsTlsMac;
@protocol LibOrgBouncycastleCryptoDigest;
@protocol LibOrgBouncycastleCryptoStreamCipher;
@protocol LibOrgBouncycastleCryptoTlsTlsContext;

@interface LibOrgBouncycastleCryptoTlsTlsStreamCipher : NSObject < LibOrgBouncycastleCryptoTlsTlsCipher > {
 @public
  id<LibOrgBouncycastleCryptoTlsTlsContext> context_;
  id<LibOrgBouncycastleCryptoStreamCipher> encryptCipher_;
  id<LibOrgBouncycastleCryptoStreamCipher> decryptCipher_;
  LibOrgBouncycastleCryptoTlsTlsMac *writeMac_;
  LibOrgBouncycastleCryptoTlsTlsMac *readMac_;
  jboolean usesNonce_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                               withLibOrgBouncycastleCryptoStreamCipher:(id<LibOrgBouncycastleCryptoStreamCipher>)clientWriteCipher
                               withLibOrgBouncycastleCryptoStreamCipher:(id<LibOrgBouncycastleCryptoStreamCipher>)serverWriteCipher
                                     withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)clientWriteDigest
                                     withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)serverWriteDigest
                                                                withInt:(jint)cipherKeySize
                                                            withBoolean:(jboolean)usesNonce;

- (IOSByteArray *)decodeCiphertextWithLong:(jlong)seqNo
                                 withShort:(jshort)type
                             withByteArray:(IOSByteArray *)ciphertext
                                   withInt:(jint)offset
                                   withInt:(jint)len;

- (IOSByteArray *)encodePlaintextWithLong:(jlong)seqNo
                                withShort:(jshort)type
                            withByteArray:(IOSByteArray *)plaintext
                                  withInt:(jint)offset
                                  withInt:(jint)len;

- (jint)getPlaintextLimitWithInt:(jint)ciphertextLimit;

#pragma mark Protected

- (void)checkMACWithLong:(jlong)seqNo
               withShort:(jshort)type
           withByteArray:(IOSByteArray *)recBuf
                 withInt:(jint)recStart
                 withInt:(jint)recEnd
           withByteArray:(IOSByteArray *)calcBuf
                 withInt:(jint)calcOff
                 withInt:(jint)calcLen;

- (void)updateIVWithLibOrgBouncycastleCryptoStreamCipher:(id<LibOrgBouncycastleCryptoStreamCipher>)cipher
                                             withBoolean:(jboolean)forEncryption
                                                withLong:(jlong)seqNo;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsStreamCipher)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsStreamCipher, context_, id<LibOrgBouncycastleCryptoTlsTlsContext>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsStreamCipher, encryptCipher_, id<LibOrgBouncycastleCryptoStreamCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsStreamCipher, decryptCipher_, id<LibOrgBouncycastleCryptoStreamCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsStreamCipher, writeMac_, LibOrgBouncycastleCryptoTlsTlsMac *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsStreamCipher, readMac_, LibOrgBouncycastleCryptoTlsTlsMac *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsStreamCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoStreamCipher_withLibOrgBouncycastleCryptoStreamCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_withBoolean_(LibOrgBouncycastleCryptoTlsTlsStreamCipher *self, id<LibOrgBouncycastleCryptoTlsTlsContext> context, id<LibOrgBouncycastleCryptoStreamCipher> clientWriteCipher, id<LibOrgBouncycastleCryptoStreamCipher> serverWriteCipher, id<LibOrgBouncycastleCryptoDigest> clientWriteDigest, id<LibOrgBouncycastleCryptoDigest> serverWriteDigest, jint cipherKeySize, jboolean usesNonce);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsStreamCipher *new_LibOrgBouncycastleCryptoTlsTlsStreamCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoStreamCipher_withLibOrgBouncycastleCryptoStreamCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_withBoolean_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, id<LibOrgBouncycastleCryptoStreamCipher> clientWriteCipher, id<LibOrgBouncycastleCryptoStreamCipher> serverWriteCipher, id<LibOrgBouncycastleCryptoDigest> clientWriteDigest, id<LibOrgBouncycastleCryptoDigest> serverWriteDigest, jint cipherKeySize, jboolean usesNonce) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsStreamCipher *create_LibOrgBouncycastleCryptoTlsTlsStreamCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoStreamCipher_withLibOrgBouncycastleCryptoStreamCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_withBoolean_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, id<LibOrgBouncycastleCryptoStreamCipher> clientWriteCipher, id<LibOrgBouncycastleCryptoStreamCipher> serverWriteCipher, id<LibOrgBouncycastleCryptoDigest> clientWriteDigest, id<LibOrgBouncycastleCryptoDigest> serverWriteDigest, jint cipherKeySize, jboolean usesNonce);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsStreamCipher)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TlsStreamCipher_H
