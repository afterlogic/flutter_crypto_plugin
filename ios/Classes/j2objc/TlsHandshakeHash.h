//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/TlsHandshakeHash.java
//

#ifndef TlsHandshakeHash_H
#define TlsHandshakeHash_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "Digest.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@protocol LibOrgBouncycastleCryptoTlsTlsContext;

@protocol LibOrgBouncycastleCryptoTlsTlsHandshakeHash < LibOrgBouncycastleCryptoDigest, JavaObject >

- (void)init__WithLibOrgBouncycastleCryptoTlsTlsContext:(id<LibOrgBouncycastleCryptoTlsTlsContext>)context OBJC_METHOD_FAMILY_NONE;

- (id<LibOrgBouncycastleCryptoTlsTlsHandshakeHash>)notifyPRFDetermined;

- (void)trackHashAlgorithmWithShort:(jshort)hashAlgorithm;

- (void)sealHashAlgorithms;

- (id<LibOrgBouncycastleCryptoTlsTlsHandshakeHash>)stopTracking;

- (id<LibOrgBouncycastleCryptoDigest>)forkPRFHash;

- (IOSByteArray *)getFinalHashWithShort:(jshort)hashAlgorithm;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsTlsHandshakeHash)

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsTlsHandshakeHash)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // TlsHandshakeHash_H
