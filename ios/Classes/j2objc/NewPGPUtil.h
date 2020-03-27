//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/util/NewPGPUtil.java
//

#ifndef NewPGPUtil_H
#define NewPGPUtil_H

#if __has_feature(nullability)
#pragma clang diagnostic push
#pragma GCC diagnostic ignored "-Wnullability"
#pragma GCC diagnostic ignored "-Wnullability-completeness"
#endif

#include "J2ObjC_header.h"

@class IOSByteArray;
@class IOSObjectArray;
@class JavaIoInputStream;
@class JavaLangLong;
@class LibOrgBouncycastleOpenpgpPGPKeyRing;
@class LibOrgBouncycastleOpenpgpPGPPublicKey;
@class LibOrgBouncycastleOpenpgpPGPPublicKeyRing;
@class LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;
@class LibOrgBouncycastleOpenpgpPGPSecretKeyRing;
@class LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;
@protocol JavaUtilSet;

@interface LibComAfterlogicPgpUtilNewPGPUtil : NSObject

#pragma mark Public

- (instancetype __nonnull)init;

+ (IOSByteArray *)getDecodedBytesWithByteArray:(IOSByteArray *)bytes;

+ (IOSByteArray *)getDecodedBytesWithJavaIoInputStream:(JavaIoInputStream *)inputStream;

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)collection
                                                                                                              withJavaLangLong:(JavaLangLong *)id_;

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)collection
                                                                                                              withJavaLangLong:(JavaLangLong *)id_;

+ (LibOrgBouncycastleOpenpgpPGPPublicKey *)getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPKeyRing:(LibOrgBouncycastleOpenpgpPGPKeyRing *)ring;

+ (LibOrgBouncycastleOpenpgpPGPPublicKey *)getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)ring;

+ (JavaIoInputStream *)getPgpDecoderInputStreamWithByteArray:(IOSByteArray *)bytes;

+ (JavaIoInputStream *)getPgpDecoderInputStreamWithJavaIoInputStream:(JavaIoInputStream *)inputStream;

+ (jboolean)keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)ring
                                                                         withLong:(jlong)keyId;

+ (jboolean)keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)ring
                                                                         withLong:(jlong)keyId;

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingArray:(IOSObjectArray *)rings;

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingArray:(IOSObjectArray *)rings;

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeyRingFromSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeys;

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)ring
                                                                                    withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)masterKey;

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)ring
                                                                                    withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)masterKey;

+ (id<JavaUtilSet>)signingKeyIdsWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)ring;

@end

J2OBJC_STATIC_INIT(LibComAfterlogicPgpUtilNewPGPUtil)

FOUNDATION_EXPORT void LibComAfterlogicPgpUtilNewPGPUtil_init(LibComAfterlogicPgpUtilNewPGPUtil *self);

FOUNDATION_EXPORT LibComAfterlogicPgpUtilNewPGPUtil *new_LibComAfterlogicPgpUtilNewPGPUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT LibComAfterlogicPgpUtilNewPGPUtil *create_LibComAfterlogicPgpUtilNewPGPUtil_init(void);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *LibComAfterlogicPgpUtilNewPGPUtil_keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingArray_(IOSObjectArray *rings);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *LibComAfterlogicPgpUtilNewPGPUtil_keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingArray_(IOSObjectArray *rings);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPPublicKeyRing *LibComAfterlogicPgpUtilNewPGPUtil_publicKeyRingFromSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRing *LibComAfterlogicPgpUtilNewPGPUtil_getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_withJavaLangLong_(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *collection, JavaLangLong *id_);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPPublicKeyRing *LibComAfterlogicPgpUtilNewPGPUtil_getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_withJavaLangLong_(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *collection, JavaLangLong *id_);

FOUNDATION_EXPORT JavaIoInputStream *LibComAfterlogicPgpUtilNewPGPUtil_getPgpDecoderInputStreamWithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT JavaIoInputStream *LibComAfterlogicPgpUtilNewPGPUtil_getPgpDecoderInputStreamWithJavaIoInputStream_(JavaIoInputStream *inputStream);

FOUNDATION_EXPORT IOSByteArray *LibComAfterlogicPgpUtilNewPGPUtil_getDecodedBytesWithByteArray_(IOSByteArray *bytes);

FOUNDATION_EXPORT IOSByteArray *LibComAfterlogicPgpUtilNewPGPUtil_getDecodedBytesWithJavaIoInputStream_(JavaIoInputStream *inputStream);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPPublicKeyRing *LibComAfterlogicPgpUtilNewPGPUtil_removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *ring, LibOrgBouncycastleOpenpgpPGPPublicKey *masterKey);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPSecretKeyRing *LibComAfterlogicPgpUtilNewPGPUtil_removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *ring, LibOrgBouncycastleOpenpgpPGPPublicKey *masterKey);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPPublicKey *LibComAfterlogicPgpUtilNewPGPUtil_getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *ring);

FOUNDATION_EXPORT LibOrgBouncycastleOpenpgpPGPPublicKey *LibComAfterlogicPgpUtilNewPGPUtil_getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPKeyRing_(LibOrgBouncycastleOpenpgpPGPKeyRing *ring);

FOUNDATION_EXPORT id<JavaUtilSet> LibComAfterlogicPgpUtilNewPGPUtil_signingKeyIdsWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *ring);

FOUNDATION_EXPORT jboolean LibComAfterlogicPgpUtilNewPGPUtil_keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLong_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *ring, jlong keyId);

FOUNDATION_EXPORT jboolean LibComAfterlogicPgpUtilNewPGPUtil_keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_withLong_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *ring, jlong keyId);

J2OBJC_TYPE_LITERAL_HEADER(LibComAfterlogicPgpUtilNewPGPUtil)


#if __has_feature(nullability)
#pragma clang diagnostic pop
#endif
#endif // NewPGPUtil_H
