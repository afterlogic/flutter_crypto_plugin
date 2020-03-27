//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPKeyRing.java
//

#ifndef PGPKeyRing_H
#define PGPKeyRing_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgTrustPacket;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@protocol JavaUtilIterator;
@protocol JavaUtilList;

@interface LibOrgBouncycastleOpenpgpPGPKeyRing : NSObject

#pragma mark Public

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream;

- (IOSByteArray *)getEncoded;

- (id<JavaUtilIterator>)getKeysWithSignaturesByWithLong:(jlong)keyID;

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKey;

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKeyWithByteArray:(IOSByteArray *)fingerprint;

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKeyWithLong:(jlong)keyID;

- (id<JavaUtilIterator>)getPublicKeys;

#pragma mark Package-Private

- (instancetype __nonnull)init;

+ (LibOrgBouncycastleBcpgTrustPacket *)readOptionalTrustPacketWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)pIn;

+ (id<JavaUtilList>)readSignaturesAndTrustWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)pIn;

+ (void)readUserIDsWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)pIn
                                            withJavaUtilList:(id<JavaUtilList>)ids
                                            withJavaUtilList:(id<JavaUtilList>)idTrusts
                                            withJavaUtilList:(id<JavaUtilList>)idSigs;

+ (LibOrgBouncycastleBcpgBCPGInputStream *)wrapWithJavaIoInputStream:(JavaIoInputStream *)inArg;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleOpenpgpPGPKeyRing)

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPKeyRing_init(LibOrgBouncycastleOpenpgpPGPKeyRing *self);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgBCPGInputStream *LibOrgBouncycastleOpenpgpPGPKeyRing_wrapWithJavaIoInputStream_(JavaIoInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgTrustPacket *LibOrgBouncycastleOpenpgpPGPKeyRing_readOptionalTrustPacketWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *pIn);

FOUNDATION_EXPORT id<JavaUtilList> LibOrgBouncycastleOpenpgpPGPKeyRing_readSignaturesAndTrustWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *pIn);

FOUNDATION_EXPORT void LibOrgBouncycastleOpenpgpPGPKeyRing_readUserIDsWithLibOrgBouncycastleBcpgBCPGInputStream_withJavaUtilList_withJavaUtilList_withJavaUtilList_(LibOrgBouncycastleBcpgBCPGInputStream *pIn, id<JavaUtilList> ids, id<JavaUtilList> idTrusts, id<JavaUtilList> idSigs);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleOpenpgpPGPKeyRing)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // PGPKeyRing_H