//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsBlockCipher.java
//

#ifndef TlsBlockCipher_H
#define TlsBlockCipher_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "TlsCipher.h"

@class IOSByteArray;
@class JavaSecuritySecureRandom;
@class LibOrgBouncycastleCryptoTlsTlsMac;
@protocol LibOrgBouncycastleCryptoBlockCipher;
@protocol LibOrgBouncycastleCryptoDigest;
@protocol LibOrgBouncycastleCryptoTlsTlsContext;

@interface LibOrgBouncycastleCryptoTlsTlsBlockCipher : NSObject < LibOrgBouncycastleCryptoTlsTlsCipher > {
 @public
  id<LibOrgBouncycastleCryptoTlsTlsContext> context_;
  IOSByteArray *randomData_;
  jboolean useExplicitIV_;
  jboolean encryptThenMAC_;
  id<LibOrgBouncycastleCryptoBlockCipher> encryptCipher_;
  id<LibOrgBouncycastleCryptoBlockCipher> decryptCipher_;
  LibOrgBouncycastleCryptoTlsTlsMac *writeMac_;
  LibOrgBouncycastleCryptoTlsTlsMac *readMac_;
}

#pragma mark Public

- (instancetype __nonnull)initWithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context
                                withLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)clientWriteCipher
                                withLibOrgBouncycastleCryptoBlockCipher:(id<LibOrgBouncycastleCryptoBlockCipher>)serverWriteCipher
                                     withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)clientWriteDigest
                                     withLibOrgBouncycastleCryptoDigest:(id<LibOrgBouncycastleCryptoDigest>)serverWriteDigest
                                                                withInt:(jint)cipherKeySize;

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

- (LibOrgBouncycastleCryptoTlsTlsMac *)getReadMac;

- (LibOrgBouncycastleCryptoTlsTlsMac *)getWriteMac;

#pragma mark Protected

- (jint)checkPaddingConstantTimeWithByteArray:(IOSByteArray *)buf
                                      withInt:(jint)off
                                      withInt:(jint)len
                                      withInt:(jint)blockSize
                                      withInt:(jint)macSize;

- (jint)chooseExtraPadBlocksWithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)r
                                                 withInt:(jint)max;

- (jint)lowestBitSetWithInt:(jint)x;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsBlockCipher)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsBlockCipher, context_, id<LibOrgBouncycastleCryptoTlsTlsContext>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsBlockCipher, randomData_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsBlockCipher, encryptCipher_, id<LibOrgBouncycastleCryptoBlockCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsBlockCipher, decryptCipher_, id<LibOrgBouncycastleCryptoBlockCipher>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsBlockCipher, writeMac_, LibOrgBouncycastleCryptoTlsTlsMac *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsTlsBlockCipher, readMac_, LibOrgBouncycastleCryptoTlsTlsMac *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsTlsBlockCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_(LibOrgBouncycastleCryptoTlsTlsBlockCipher *self, id<LibOrgBouncycastleCryptoTlsTlsContext> context, id<LibOrgBouncycastleCryptoBlockCipher> clientWriteCipher, id<LibOrgBouncycastleCryptoBlockCipher> serverWriteCipher, id<LibOrgBouncycastleCryptoDigest> clientWriteDigest, id<LibOrgBouncycastleCryptoDigest> serverWriteDigest, jint cipherKeySize);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsBlockCipher *new_LibOrgBouncycastleCryptoTlsTlsBlockCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, id<LibOrgBouncycastleCryptoBlockCipher> clientWriteCipher, id<LibOrgBouncycastleCryptoBlockCipher> serverWriteCipher, id<LibOrgBouncycastleCryptoDigest> clientWriteDigest, id<LibOrgBouncycastleCryptoDigest> serverWriteDigest, jint cipherKeySize) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsTlsBlockCipher *create_LibOrgBouncycastleCryptoTlsTlsBlockCipher_initWithLibOrgBouncycastleCryptoTlsTlsContext_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoBlockCipher_withLibOrgBouncycastleCryptoDigest_withLibOrgBouncycastleCryptoDigest_withInt_(id<LibOrgBouncycastleCryptoTlsTlsContext> context, id<LibOrgBouncycastleCryptoBlockCipher> clientWriteCipher, id<LibOrgBouncycastleCryptoBlockCipher> serverWriteCipher, id<LibOrgBouncycastleCryptoDigest> clientWriteDigest, id<LibOrgBouncycastleCryptoDigest> serverWriteDigest, jint cipherKeySize);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsBlockCipher)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TlsBlockCipher_H