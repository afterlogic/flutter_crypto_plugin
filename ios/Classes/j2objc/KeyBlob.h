//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/gpg/keybox/KeyBlob.java
//

#ifndef KeyBlob_H
#define KeyBlob_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "Blob.h"
#include "J2ObjC_header.h"

@class IOSByteArray;
@class LibOrgBouncycastleGpgKeyboxBlobType;
@class LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer;
@protocol JavaUtilList;
@protocol LibOrgBouncycastleGpgKeyboxBlobVerifier;

@interface LibOrgBouncycastleGpgKeyboxKeyBlob : LibOrgBouncycastleGpgKeyboxBlob

#pragma mark Public

- (jint)getAllValidity;

- (jint)getAssignedOwnerTrust;

- (jlong)getBlobCreatedAt;

- (jint)getBlobFlags;

- (IOSByteArray *)getChecksum;

- (id<JavaUtilList>)getExpirationTime;

- (IOSByteArray *)getKeyBytes;

- (id<JavaUtilList>)getKeyInformation;

- (jint)getKeyNumber;

- (jlong)getNewestTimestamp;

- (jint)getNumberOfSignatures;

- (jint)getNumberOfUserIDs;

- (jlong)getRecheckAfter;

- (IOSByteArray *)getReserveBytes;

- (IOSByteArray *)getSerialNumber;

- (id<JavaUtilList>)getUserIds;

#pragma mark Protected

- (instancetype __nonnull)initWithInt:(jint)base
                             withLong:(jlong)length
withLibOrgBouncycastleGpgKeyboxBlobType:(LibOrgBouncycastleGpgKeyboxBlobType *)type
                              withInt:(jint)version_
                              withInt:(jint)blobFlags
                              withInt:(jint)keyNumber
                     withJavaUtilList:(id<JavaUtilList>)keyInformation
                        withByteArray:(IOSByteArray *)serialNumber
                              withInt:(jint)numberOfUserIDs
                     withJavaUtilList:(id<JavaUtilList>)userIds
                              withInt:(jint)numberOfSignatures
                     withJavaUtilList:(id<JavaUtilList>)expirationTime
                              withInt:(jint)assignedOwnerTrust
                              withInt:(jint)allValidity
                             withLong:(jlong)recheckAfter
                             withLong:(jlong)newestTimestamp
                             withLong:(jlong)blobCreatedAt
                        withByteArray:(IOSByteArray *)keyBytes
                        withByteArray:(IOSByteArray *)reserveBytes
                        withByteArray:(IOSByteArray *)checksum;

#pragma mark Package-Private

+ (void)verifyDigestWithInt:(jint)base
                   withLong:(jlong)length
withLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer:(LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *)buffer
withLibOrgBouncycastleGpgKeyboxBlobVerifier:(id<LibOrgBouncycastleGpgKeyboxBlobVerifier>)blobVerifier;

// Disallowed inherited constructors, do not use.

- (instancetype __nonnull)initWithInt:(jint)arg0
                             withLong:(jlong)arg1
withLibOrgBouncycastleGpgKeyboxBlobType:(LibOrgBouncycastleGpgKeyboxBlobType *)arg2
                              withInt:(jint)arg3 NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleGpgKeyboxKeyBlob)

FOUNDATION_EXPORT void LibOrgBouncycastleGpgKeyboxKeyBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(LibOrgBouncycastleGpgKeyboxKeyBlob *self, jint base, jlong length, LibOrgBouncycastleGpgKeyboxBlobType *type, jint version_, jint blobFlags, jint keyNumber, id<JavaUtilList> keyInformation, IOSByteArray *serialNumber, jint numberOfUserIDs, id<JavaUtilList> userIds, jint numberOfSignatures, id<JavaUtilList> expirationTime, jint assignedOwnerTrust, jint allValidity, jlong recheckAfter, jlong newestTimestamp, jlong blobCreatedAt, IOSByteArray *keyBytes, IOSByteArray *reserveBytes, IOSByteArray *checksum);

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxKeyBlob *new_LibOrgBouncycastleGpgKeyboxKeyBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(jint base, jlong length, LibOrgBouncycastleGpgKeyboxBlobType *type, jint version_, jint blobFlags, jint keyNumber, id<JavaUtilList> keyInformation, IOSByteArray *serialNumber, jint numberOfUserIDs, id<JavaUtilList> userIds, jint numberOfSignatures, id<JavaUtilList> expirationTime, jint assignedOwnerTrust, jint allValidity, jlong recheckAfter, jlong newestTimestamp, jlong blobCreatedAt, IOSByteArray *keyBytes, IOSByteArray *reserveBytes, IOSByteArray *checksum) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibOrgBouncycastleGpgKeyboxKeyBlob *create_LibOrgBouncycastleGpgKeyboxKeyBlob_initWithInt_withLong_withLibOrgBouncycastleGpgKeyboxBlobType_withInt_withInt_withInt_withJavaUtilList_withByteArray_withInt_withJavaUtilList_withInt_withJavaUtilList_withInt_withInt_withLong_withLong_withLong_withByteArray_withByteArray_withByteArray_(jint base, jlong length, LibOrgBouncycastleGpgKeyboxBlobType *type, jint version_, jint blobFlags, jint keyNumber, id<JavaUtilList> keyInformation, IOSByteArray *serialNumber, jint numberOfUserIDs, id<JavaUtilList> userIds, jint numberOfSignatures, id<JavaUtilList> expirationTime, jint assignedOwnerTrust, jint allValidity, jlong recheckAfter, jlong newestTimestamp, jlong blobCreatedAt, IOSByteArray *keyBytes, IOSByteArray *reserveBytes, IOSByteArray *checksum);

FOUNDATION_EXPORT void LibOrgBouncycastleGpgKeyboxKeyBlob_verifyDigestWithInt_withLong_withLibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer_withLibOrgBouncycastleGpgKeyboxBlobVerifier_(jint base, jlong length, LibOrgBouncycastleGpgKeyboxKeyBoxByteBuffer *buffer, id<LibOrgBouncycastleGpgKeyboxBlobVerifier> blobVerifier);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleGpgKeyboxKeyBlob)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // KeyBlob_H
