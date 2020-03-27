//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/tls/SecurityParameters.java
//

#ifndef SecurityParameters_H
#define SecurityParameters_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;

@interface LibOrgBouncycastleCryptoTlsSecurityParameters : NSObject {
 @public
  jint entity_;
  jint cipherSuite_;
  jshort compressionAlgorithm_;
  jint prfAlgorithm_;
  jint verifyDataLength_;
  IOSByteArray *masterSecret_;
  IOSByteArray *clientRandom_;
  IOSByteArray *serverRandom_;
  IOSByteArray *sessionHash_;
  IOSByteArray *pskIdentity_;
  IOSByteArray *srpIdentity_;
  jshort maxFragmentLength_;
  jboolean truncatedHMac_;
  jboolean encryptThenMAC_;
  jboolean extendedMasterSecret_;
}

#pragma mark Public

- (instancetype __nonnull)init;

- (jint)getCipherSuite;

- (IOSByteArray *)getClientRandom;

- (jshort)getCompressionAlgorithm;

- (jint)getEntity;

- (IOSByteArray *)getMasterSecret;

- (jint)getPrfAlgorithm;

- (IOSByteArray *)getPskIdentity;

- (IOSByteArray *)getPSKIdentity;

- (IOSByteArray *)getServerRandom;

- (IOSByteArray *)getSessionHash;

- (IOSByteArray *)getSRPIdentity;

- (jint)getVerifyDataLength;

- (jboolean)isExtendedMasterSecret;

#pragma mark Package-Private

- (void)clear;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoTlsSecurityParameters)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsSecurityParameters, masterSecret_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsSecurityParameters, clientRandom_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsSecurityParameters, serverRandom_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsSecurityParameters, sessionHash_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsSecurityParameters, pskIdentity_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoTlsSecurityParameters, srpIdentity_, IOSByteArray *)

FOUNDATION_EXPORT void LibOrgBouncycastleCryptoTlsSecurityParameters_init(LibOrgBouncycastleCryptoTlsSecurityParameters *self);

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsSecurityParameters *new_LibOrgBouncycastleCryptoTlsSecurityParameters_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleCryptoTlsSecurityParameters *create_LibOrgBouncycastleCryptoTlsSecurityParameters_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoTlsSecurityParameters)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SecurityParameters_H
