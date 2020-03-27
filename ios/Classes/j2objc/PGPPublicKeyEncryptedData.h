//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPPublicKeyEncryptedData.java
//

#ifndef PGPPublicKeyEncryptedData_H
#define PGPPublicKeyEncryptedData_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"
#include "PGPEncryptedData.h"

@class JavaIoInputStream;
@class LibOrgBouncycastleBcpgInputStreamPacket;
@class LibOrgBouncycastleBcpgPublicKeyEncSessionPacket;
@protocol LibOrgBouncycastleOpenpgpOperatorPublicKeyDataDecryptorFactory;

@interface LibOrgBouncycastleOpenpgpPGPPublicKeyEncryptedData : LibOrgBouncycastleOpenpgpPGPEncryptedData {
 @public
  LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *keyData_;
}

#pragma mark Public

- (JavaIoInputStream *)getDataStreamWithLibOrgBouncycastleOpenpgpOperatorPublicKeyDataDecryptorFactory:(id<LibOrgBouncycastleOpenpgpOperatorPublicKeyDataDecryptorFactory>)dataDecryptorFactory;

- (jlong)getKeyID;

- (jint)getSymmetricAlgorithmWithLibOrgBouncycastleOpenpgpOperatorPublicKeyDataDecryptorFactory:(id<LibOrgBouncycastleOpenpgpOperatorPublicKeyDataDecryptorFactory>)dataDecryptorFactory;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgPublicKeyEncSessionPacket:(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *)keyData
                                      withLibOrgBouncycastleBcpgInputStreamPacket:(LibOrgBouncycastleBcpgInputStreamPacket *)encData;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgInputStreamPacket:(LibOrgBouncycastleBcpgInputStreamPacket *)arg0 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPPublicKeyEncryptedData)

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPPublicKeyEncryptedData, keyData_, LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPPublicKeyEncryptedData_initWithLibOrgBouncycastleBcpgPublicKeyEncSessionPacket_withLibOrgBouncycastleBcpgInputStreamPacket_(LibOrgBouncycastleOpenpgpPGPPublicKeyEncryptedData *self, LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *keyData, LibOrgBouncycastleBcpgInputStreamPacket *encData);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPPublicKeyEncryptedData *new_LibOrgBouncycastleOpenpgpPGPPublicKeyEncryptedData_initWithLibOrgBouncycastleBcpgPublicKeyEncSessionPacket_withLibOrgBouncycastleBcpgInputStreamPacket_(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *keyData, LibOrgBouncycastleBcpgInputStreamPacket *encData) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPPublicKeyEncryptedData *create_LibOrgBouncycastleOpenpgpPGPPublicKeyEncryptedData_initWithLibOrgBouncycastleBcpgPublicKeyEncSessionPacket_withLibOrgBouncycastleBcpgInputStreamPacket_(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *keyData, LibOrgBouncycastleBcpgInputStreamPacket *encData);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPPublicKeyEncryptedData)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPPublicKeyEncryptedData_H
