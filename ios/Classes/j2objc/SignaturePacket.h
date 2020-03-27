//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/SignaturePacket.java
//

#ifndef SignaturePacket_H
#define SignaturePacket_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "ContainedPacket.h"
#include "J2ObjC_header.h"
#include "PublicKeyAlgorithmTags.h"

@class IOSByteArray;
@class IOSObjectArray;
@class LibOrgBouncycastleBcpgBCPGInputStream;
@class LibOrgBouncycastleBcpgBCPGOutputStream;

@interface LibOrgBouncycastleBcpgSignaturePacket : LibOrgBouncycastleBcpgContainedPacket < LibOrgBouncycastleBcpgPublicKeyAlgorithmTags >

#pragma mark Public

- (instancetype __nonnull)initWithInt:(jint)version_
                              withInt:(jint)signatureType
                             withLong:(jlong)keyID
                              withInt:(jint)keyAlgorithm
                              withInt:(jint)hashAlgorithm
                             withLong:(jlong)creationTime
                        withByteArray:(IOSByteArray *)fingerPrint
withLibOrgBouncycastleBcpgMPIntegerArray:(IOSObjectArray *)signature;

- (instancetype __nonnull)initWithInt:(jint)version_
                              withInt:(jint)signatureType
                             withLong:(jlong)keyID
                              withInt:(jint)keyAlgorithm
                              withInt:(jint)hashAlgorithm
withLibOrgBouncycastleBcpgSignatureSubpacketArray:(IOSObjectArray *)hashedData
withLibOrgBouncycastleBcpgSignatureSubpacketArray:(IOSObjectArray *)unhashedData
                        withByteArray:(IOSByteArray *)fingerPrint
withLibOrgBouncycastleBcpgMPIntegerArray:(IOSObjectArray *)signature;

- (instancetype __nonnull)initWithInt:(jint)signatureType
                             withLong:(jlong)keyID
                              withInt:(jint)keyAlgorithm
                              withInt:(jint)hashAlgorithm
withLibOrgBouncycastleBcpgSignatureSubpacketArray:(IOSObjectArray *)hashedData
withLibOrgBouncycastleBcpgSignatureSubpacketArray:(IOSObjectArray *)unhashedData
                        withByteArray:(IOSByteArray *)fingerPrint
withLibOrgBouncycastleBcpgMPIntegerArray:(IOSObjectArray *)signature;

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg;

+ (LibOrgBouncycastleBcpgSignaturePacket *)fromByteArrayWithByteArray:(IOSByteArray *)data;

- (jlong)getCreationTime;

- (jint)getHashAlgorithm;

- (IOSObjectArray *)getHashedSubPackets;

- (jint)getKeyAlgorithm;

- (jlong)getKeyID;

- (IOSObjectArray *)getSignature;

- (IOSByteArray *)getSignatureBytes;

- (IOSByteArray *)getSignatureTrailer;

- (jint)getSignatureType;

- (IOSObjectArray *)getUnhashedSubPackets;

- (jint)getVersion;

#pragma mark Package-Private

- (instancetype __nonnull)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleBcpgSignaturePacket)

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgSignaturePacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSignaturePacket *new_LibOrgBouncycastleBcpgSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSignaturePacket *create_LibOrgBouncycastleBcpgSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(LibOrgBouncycastleBcpgSignaturePacket *self, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSignaturePacket *new_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSignaturePacket *create_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLong_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(LibOrgBouncycastleBcpgSignaturePacket *self, jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, jlong creationTime, IOSByteArray *fingerPrint, IOSObjectArray *signature);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSignaturePacket *new_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLong_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, jlong creationTime, IOSByteArray *fingerPrint, IOSObjectArray *signature) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSignaturePacket *create_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLong_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, jlong creationTime, IOSByteArray *fingerPrint, IOSObjectArray *signature);

FOUNDATION_EXPORT void LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(LibOrgBouncycastleBcpgSignaturePacket *self, jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSignaturePacket *new_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSignaturePacket *create_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withLibOrgBouncycastleBcpgSignatureSubpacketArray_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(jint version_, jint signatureType, jlong keyID, jint keyAlgorithm, jint hashAlgorithm, IOSObjectArray *hashedData, IOSObjectArray *unhashedData, IOSByteArray *fingerPrint, IOSObjectArray *signature);

FOUNDATION_EXPORT LibOrgBouncycastleBcpgSignaturePacket *LibOrgBouncycastleBcpgSignaturePacket_fromByteArrayWithByteArray_(IOSByteArray *data);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleBcpgSignaturePacket)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // SignaturePacket_H