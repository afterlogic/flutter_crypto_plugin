//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/util/NewPGPUtil.java
//

#include "And.h"
#include "BcKeyFingerprintCalculator.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyFlag.h"
#include "NewPGPUtil.h"
#include "NoRevocation.h"
#include "PGPException.h"
#include "PGPKeyRing.h"
#include "PGPPublicKey.h"
#include "PGPPublicKeyRing.h"
#include "PGPPublicKeyRingCollection.h"
#include "PGPSecretKey.h"
#include "PGPSecretKeyRing.h"
#include "PGPSecretKeyRingCollection.h"
#include "PGPSignature.h"
#include "PGPSignatureSubpacketVector.h"
#include "PGPUtil.h"
#include "PublicKeySelectionStrategy.h"
#include "SignedByMasterKey.h"
#include "Streams.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/InputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Long.h"
#include "java/util/Arrays.h"
#include "java/util/HashSet.h"
#include "java/util/Iterator.h"
#include "java/util/List.h"
#include "java/util/Set.h"
#include "java/util/logging/Level.h"
#include "java/util/logging/Logger.h"

inline JavaUtilLoggingLogger *LibComAfterlogicPgpUtilNewPGPUtil_get_LOGGER(void);
static JavaUtilLoggingLogger *LibComAfterlogicPgpUtilNewPGPUtil_LOGGER;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibComAfterlogicPgpUtilNewPGPUtil, LOGGER, JavaUtilLoggingLogger *)

J2OBJC_INITIALIZED_DEFN(LibComAfterlogicPgpUtilNewPGPUtil)

@implementation LibComAfterlogicPgpUtilNewPGPUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpUtilNewPGPUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingArray:(IOSObjectArray *)rings {
  return LibComAfterlogicPgpUtilNewPGPUtil_keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingArray_(rings);
}

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingArray:(IOSObjectArray *)rings {
  return LibComAfterlogicPgpUtilNewPGPUtil_keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingArray_(rings);
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)publicKeyRingFromSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)secretKeys {
  return LibComAfterlogicPgpUtilNewPGPUtil_publicKeyRingFromSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(secretKeys);
}

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)collection
                                                                                                              withJavaLangLong:(JavaLangLong *)id_ {
  return LibComAfterlogicPgpUtilNewPGPUtil_getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_withJavaLangLong_(collection, id_);
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)collection
                                                                                                              withJavaLangLong:(JavaLangLong *)id_ {
  return LibComAfterlogicPgpUtilNewPGPUtil_getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_withJavaLangLong_(collection, id_);
}

+ (JavaIoInputStream *)getPgpDecoderInputStreamWithByteArray:(IOSByteArray *)bytes {
  return LibComAfterlogicPgpUtilNewPGPUtil_getPgpDecoderInputStreamWithByteArray_(bytes);
}

+ (JavaIoInputStream *)getPgpDecoderInputStreamWithJavaIoInputStream:(JavaIoInputStream *)inputStream {
  return LibComAfterlogicPgpUtilNewPGPUtil_getPgpDecoderInputStreamWithJavaIoInputStream_(inputStream);
}

+ (IOSByteArray *)getDecodedBytesWithByteArray:(IOSByteArray *)bytes {
  return LibComAfterlogicPgpUtilNewPGPUtil_getDecodedBytesWithByteArray_(bytes);
}

+ (IOSByteArray *)getDecodedBytesWithJavaIoInputStream:(JavaIoInputStream *)inputStream {
  return LibComAfterlogicPgpUtilNewPGPUtil_getDecodedBytesWithJavaIoInputStream_(inputStream);
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)ring
                                                                                    withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)masterKey {
  return LibComAfterlogicPgpUtilNewPGPUtil_removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(ring, masterKey);
}

+ (LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)ring
                                                                                    withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)masterKey {
  return LibComAfterlogicPgpUtilNewPGPUtil_removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(ring, masterKey);
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKey *)getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)ring {
  return LibComAfterlogicPgpUtilNewPGPUtil_getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(ring);
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKey *)getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPKeyRing:(LibOrgBouncycastleOpenpgpPGPKeyRing *)ring {
  return LibComAfterlogicPgpUtilNewPGPUtil_getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPKeyRing_(ring);
}

+ (id<JavaUtilSet>)signingKeyIdsWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)ring {
  return LibComAfterlogicPgpUtilNewPGPUtil_signingKeyIdsWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(ring);
}

+ (jboolean)keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)ring
                                                                         withLong:(jlong)keyId {
  return LibComAfterlogicPgpUtilNewPGPUtil_keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLong_(ring, keyId);
}

+ (jboolean)keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)ring
                                                                         withLong:(jlong)keyId {
  return LibComAfterlogicPgpUtilNewPGPUtil_keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_withLong_(ring, keyId);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;", 0x89, 0, 1, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;", 0x89, 0, 3, 2, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", 0x9, 4, 5, 6, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", 0x9, 7, 8, 9, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", 0x9, 7, 10, 9, -1, -1, -1 },
    { NULL, "LJavaIoInputStream;", 0x9, 11, 12, 13, -1, -1, -1 },
    { NULL, "LJavaIoInputStream;", 0x9, 11, 14, 13, -1, -1, -1 },
    { NULL, "[B", 0x9, 15, 12, 13, -1, -1, -1 },
    { NULL, "[B", 0x9, 15, 14, 13, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", 0x9, 16, 17, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", 0x9, 16, 18, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x9, 19, 20, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x9, 19, 21, -1, -1, -1, -1 },
    { NULL, "LJavaUtilSet;", 0x9, 22, 5, -1, 23, -1, -1 },
    { NULL, "Z", 0x9, 24, 25, -1, -1, -1, -1 },
    { NULL, "Z", 0x9, 24, 26, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingArray:);
  methods[2].selector = @selector(keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingArray:);
  methods[3].selector = @selector(publicKeyRingFromSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:);
  methods[4].selector = @selector(getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:withJavaLangLong:);
  methods[5].selector = @selector(getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:withJavaLangLong:);
  methods[6].selector = @selector(getPgpDecoderInputStreamWithByteArray:);
  methods[7].selector = @selector(getPgpDecoderInputStreamWithJavaIoInputStream:);
  methods[8].selector = @selector(getDecodedBytesWithByteArray:);
  methods[9].selector = @selector(getDecodedBytesWithJavaIoInputStream:);
  methods[10].selector = @selector(removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:withLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[11].selector = @selector(removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:withLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[12].selector = @selector(getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:);
  methods[13].selector = @selector(getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPKeyRing:);
  methods[14].selector = @selector(signingKeyIdsWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:);
  methods[15].selector = @selector(keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:withLong:);
  methods[16].selector = @selector(keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:withLong:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "LOGGER", "LJavaUtilLoggingLogger;", .constantValue.asLong = 0, 0x1a, -1, 27, -1, -1 },
  };
  static const void *ptrTable[] = { "keyRingsToKeyRingCollection", "[LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", "LJavaIoIOException;LLibOrgBouncycastleOpenpgpPGPException;", "[LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", "publicKeyRingFromSecretKeyRing", "LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", "LLibOrgBouncycastleOpenpgpPGPException;LJavaIoIOException;", "getKeyRingFromCollection", "LLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;LJavaLangLong;", "LLibOrgBouncycastleOpenpgpPGPException;", "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;LJavaLangLong;", "getPgpDecoderInputStream", "[B", "LJavaIoIOException;", "LJavaIoInputStream;", "getDecodedBytes", "removeUnassociatedKeysFromKeyRing", "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;LLibOrgBouncycastleOpenpgpPGPPublicKey;", "LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;LLibOrgBouncycastleOpenpgpPGPPublicKey;", "getMasterKeyFrom", "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", "LLibOrgBouncycastleOpenpgpPGPKeyRing;", "signingKeyIds", "(Llib/org/bouncycastle/openpgp/PGPSecretKeyRing;)Ljava/util/Set<Ljava/lang/Long;>;", "keyRingContainsKeyWithId", "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;J", "LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;J", &LibComAfterlogicPgpUtilNewPGPUtil_LOGGER };
  static const J2ObjcClassInfo _LibComAfterlogicPgpUtilNewPGPUtil = { "NewPGPUtil", "lib.com.afterlogic.pgp.util", ptrTable, methods, fields, 7, 0x1, 17, 1, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpUtilNewPGPUtil;
}

+ (void)initialize {
  if (self == [LibComAfterlogicPgpUtilNewPGPUtil class]) {
    LibComAfterlogicPgpUtilNewPGPUtil_LOGGER = JavaUtilLoggingLogger_getLoggerWithNSString_([LibComAfterlogicPgpUtilNewPGPUtil_class_() getName]);
    J2OBJC_SET_INITIALIZED(LibComAfterlogicPgpUtilNewPGPUtil)
  }
}

@end

void LibComAfterlogicPgpUtilNewPGPUtil_init(LibComAfterlogicPgpUtilNewPGPUtil *self) {
  NSObject_init(self);
}

LibComAfterlogicPgpUtilNewPGPUtil *new_LibComAfterlogicPgpUtilNewPGPUtil_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpUtilNewPGPUtil, init)
}

LibComAfterlogicPgpUtilNewPGPUtil *create_LibComAfterlogicPgpUtilNewPGPUtil_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpUtilNewPGPUtil, init)
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *LibComAfterlogicPgpUtilNewPGPUtil_keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingArray_(IOSObjectArray *rings) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  return new_LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_initWithJavaUtilCollection_(JavaUtilArrays_asListWithNSObjectArray_(rings));
}

LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *LibComAfterlogicPgpUtilNewPGPUtil_keyRingsToKeyRingCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingArray_(IOSObjectArray *rings) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  return new_LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_initWithJavaUtilCollection_(JavaUtilArrays_asListWithNSObjectArray_(rings));
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *LibComAfterlogicPgpUtilNewPGPUtil_publicKeyRingFromSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *secretKeys) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  JavaIoByteArrayOutputStream *buffer = new_JavaIoByteArrayOutputStream_initWithInt_(512);
  for (LibOrgBouncycastleOpenpgpPGPSecretKey * __strong secretKey in nil_chk(secretKeys)) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *publicKey = [((LibOrgBouncycastleOpenpgpPGPSecretKey *) nil_chk(secretKey)) getPublicKey];
    if (publicKey != nil) {
      [publicKey encodeWithJavaIoOutputStream:buffer withBoolean:false];
    }
  }
  return new_LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_([buffer toByteArray], new_LibOrgBouncycastleOpenpgpOperatorBcBcKeyFingerprintCalculator_init());
}

LibOrgBouncycastleOpenpgpPGPSecretKeyRing *LibComAfterlogicPgpUtilNewPGPUtil_getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_withJavaLangLong_(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *collection, JavaLangLong *id_) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  LibOrgBouncycastleOpenpgpPGPSecretKeyRing *uncleanedRing = [((LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *) nil_chk(collection)) getSecretKeyRingWithLong:[((JavaLangLong *) nil_chk(id_)) longLongValue]];
  id<JavaUtilSet> signedKeyIds = new_JavaUtilHashSet_init();
  [signedKeyIds addWithId:id_];
  id<JavaUtilIterator> signedPubKeys = [((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk(uncleanedRing)) getKeysWithSignaturesByWithLong:[id_ longLongValue]];
  while ([((id<JavaUtilIterator>) nil_chk(signedPubKeys)) hasNext]) {
    [signedKeyIds addWithId:JavaLangLong_valueOfWithLong_([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk([signedPubKeys next])) getKeyID])];
  }
  LibOrgBouncycastleOpenpgpPGPSecretKeyRing *cleanedRing = uncleanedRing;
  id<JavaUtilIterator> secretKeys = [uncleanedRing getSecretKeys];
  while ([((id<JavaUtilIterator>) nil_chk(secretKeys)) hasNext]) {
    LibOrgBouncycastleOpenpgpPGPSecretKey *secretKey = [secretKeys next];
    if (![signedKeyIds containsWithId:JavaLangLong_valueOfWithLong_([((LibOrgBouncycastleOpenpgpPGPSecretKey *) nil_chk(secretKey)) getKeyID])]) {
      cleanedRing = LibOrgBouncycastleOpenpgpPGPSecretKeyRing_removeSecretKeyWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_withLibOrgBouncycastleOpenpgpPGPSecretKey_(cleanedRing, secretKey);
    }
  }
  return cleanedRing;
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *LibComAfterlogicPgpUtilNewPGPUtil_getKeyRingFromCollectionWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_withJavaLangLong_(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *collection, JavaLangLong *id_) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  LibOrgBouncycastleOpenpgpPGPPublicKey *key = [((LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *) nil_chk(collection)) getPublicKeyWithLong:[((JavaLangLong *) nil_chk(id_)) longLongValue]];
  return LibComAfterlogicPgpUtilNewPGPUtil_removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_([collection getPublicKeyRingWithLong:[id_ longLongValue]], key);
}

JavaIoInputStream *LibComAfterlogicPgpUtilNewPGPUtil_getPgpDecoderInputStreamWithByteArray_(IOSByteArray *bytes) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  return LibComAfterlogicPgpUtilNewPGPUtil_getPgpDecoderInputStreamWithJavaIoInputStream_(new_JavaIoByteArrayInputStream_initWithByteArray_(bytes));
}

JavaIoInputStream *LibComAfterlogicPgpUtilNewPGPUtil_getPgpDecoderInputStreamWithJavaIoInputStream_(JavaIoInputStream *inputStream) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  return LibOrgBouncycastleOpenpgpPGPUtil_getDecoderStreamWithJavaIoInputStream_(inputStream);
}

IOSByteArray *LibComAfterlogicPgpUtilNewPGPUtil_getDecodedBytesWithByteArray_(IOSByteArray *bytes) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  JavaIoByteArrayOutputStream *buffer = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleUtilIoStreams_pipeAllWithJavaIoInputStream_withJavaIoOutputStream_(LibComAfterlogicPgpUtilNewPGPUtil_getPgpDecoderInputStreamWithByteArray_(bytes), buffer);
  return [buffer toByteArray];
}

IOSByteArray *LibComAfterlogicPgpUtilNewPGPUtil_getDecodedBytesWithJavaIoInputStream_(JavaIoInputStream *inputStream) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  JavaIoByteArrayOutputStream *buffer = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleUtilIoStreams_pipeAllWithJavaIoInputStream_withJavaIoOutputStream_(inputStream, buffer);
  return LibComAfterlogicPgpUtilNewPGPUtil_getDecodedBytesWithByteArray_([buffer toByteArray]);
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *LibComAfterlogicPgpUtilNewPGPUtil_removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *ring, LibOrgBouncycastleOpenpgpPGPPublicKey *masterKey) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  if (![((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(masterKey)) isMasterKey]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Given key is not a master key.");
  }
  LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *selector = new_LibComAfterlogicPgpKeySelectionKeyUtilAnd_PubKeySelectionStrategy_initWithLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_withLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_(new_LibComAfterlogicPgpKeySelectionKeyImplSignedByMasterKey_PubkeySelectionStrategy_init(), new_LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy_init());
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing *cleaned = ring;
  id<JavaUtilIterator> publicKeys = [((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk(ring)) getPublicKeys];
  while ([((id<JavaUtilIterator>) nil_chk(publicKeys)) hasNext]) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *publicKey = [publicKeys next];
    if (![selector acceptWithId:masterKey withId:publicKey]) {
      cleaned = LibOrgBouncycastleOpenpgpPGPPublicKeyRing_removePublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(cleaned, publicKey);
    }
  }
  return cleaned;
}

LibOrgBouncycastleOpenpgpPGPSecretKeyRing *LibComAfterlogicPgpUtilNewPGPUtil_removeUnassociatedKeysFromKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *ring, LibOrgBouncycastleOpenpgpPGPPublicKey *masterKey) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  if (![((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(masterKey)) isMasterKey]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Given key is not a master key.");
  }
  LibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy *selector = new_LibComAfterlogicPgpKeySelectionKeyUtilAnd_PubKeySelectionStrategy_initWithLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_withLibComAfterlogicPgpKeySelectionKeyPublicKeySelectionStrategy_(new_LibComAfterlogicPgpKeySelectionKeyImplSignedByMasterKey_PubkeySelectionStrategy_init(), new_LibComAfterlogicPgpKeySelectionKeyImplNoRevocation_PubKeySelectionStrategy_init());
  LibOrgBouncycastleOpenpgpPGPSecretKeyRing *cleaned = ring;
  id<JavaUtilIterator> secretKeys = [((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk(ring)) getSecretKeys];
  while ([((id<JavaUtilIterator>) nil_chk(secretKeys)) hasNext]) {
    LibOrgBouncycastleOpenpgpPGPSecretKey *secretKey = [secretKeys next];
    if (![selector acceptWithId:masterKey withId:[((LibOrgBouncycastleOpenpgpPGPSecretKey *) nil_chk(secretKey)) getPublicKey]]) {
      cleaned = LibOrgBouncycastleOpenpgpPGPSecretKeyRing_removeSecretKeyWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_withLibOrgBouncycastleOpenpgpPGPSecretKey_(cleaned, secretKey);
    }
  }
  return cleaned;
}

LibOrgBouncycastleOpenpgpPGPPublicKey *LibComAfterlogicPgpUtilNewPGPUtil_getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *ring) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  id<JavaUtilIterator> it = [((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk(ring)) getPublicKeys];
  while ([((id<JavaUtilIterator>) nil_chk(it)) hasNext]) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *k = [it next];
    if ([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(k)) isMasterKey]) {
      return k;
    }
  }
  return nil;
}

LibOrgBouncycastleOpenpgpPGPPublicKey *LibComAfterlogicPgpUtilNewPGPUtil_getMasterKeyFromWithLibOrgBouncycastleOpenpgpPGPKeyRing_(LibOrgBouncycastleOpenpgpPGPKeyRing *ring) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  id<JavaUtilIterator> it = [((LibOrgBouncycastleOpenpgpPGPKeyRing *) nil_chk(ring)) getPublicKeys];
  while ([((id<JavaUtilIterator>) nil_chk(it)) hasNext]) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *k = [it next];
    if ([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(k)) isMasterKey]) {
      return k;
    }
  }
  return nil;
}

id<JavaUtilSet> LibComAfterlogicPgpUtilNewPGPUtil_signingKeyIdsWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *ring) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  id<JavaUtilSet> ids = new_JavaUtilHashSet_init();
  id<JavaUtilIterator> it = [((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk(ring)) getPublicKeys];
  while ([((id<JavaUtilIterator>) nil_chk(it)) hasNext]) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *k = [it next];
    jboolean signingKey = false;
    id<JavaUtilIterator> sit = [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(k)) getSignatures];
    while ([((id<JavaUtilIterator>) nil_chk(sit)) hasNext]) {
      id n = [sit next];
      if (!([n isKindOfClass:[LibOrgBouncycastleOpenpgpPGPSignature class]])) {
        continue;
      }
      LibOrgBouncycastleOpenpgpPGPSignature *s = (LibOrgBouncycastleOpenpgpPGPSignature *) cast_chk(n, [LibOrgBouncycastleOpenpgpPGPSignature class]);
      if (![((LibOrgBouncycastleOpenpgpPGPSignature *) nil_chk(s)) hasSubpackets]) {
        continue;
      }
      @try {
        [s verifyCertificationWithLibOrgBouncycastleOpenpgpPGPPublicKey:[ring getPublicKeyWithLong:[s getKeyID]]];
      }
      @catch (LibOrgBouncycastleOpenpgpPGPException *e) {
        [((JavaUtilLoggingLogger *) nil_chk(LibComAfterlogicPgpUtilNewPGPUtil_LOGGER)) logWithJavaUtilLoggingLevel:JreLoadStatic(JavaUtilLoggingLevel, WARNING) withNSString:JreStrcat("$$$$", @"Could not verify signature on ", JavaLangLong_toHexStringWithLong_([k getKeyID]), @" made by ", JavaLangLong_toHexStringWithLong_([s getKeyID]))];
        continue;
      }
      LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *hashed = [s getHashedSubPackets];
      if ([((id<JavaUtilList>) nil_chk(LibComAfterlogicPgpAlgorithmKeyFlag_fromIntegerWithInt_([((LibOrgBouncycastleOpenpgpPGPSignatureSubpacketVector *) nil_chk(hashed)) getKeyFlags]))) containsWithId:JreLoadEnum(LibComAfterlogicPgpAlgorithmKeyFlag, SIGN_DATA)]) {
        signingKey = true;
        break;
      }
    }
    if (signingKey) {
      [ids addWithId:JavaLangLong_valueOfWithLong_([k getKeyID])];
    }
  }
  return ids;
}

jboolean LibComAfterlogicPgpUtilNewPGPUtil_keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLong_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *ring, jlong keyId) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  return [((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk(ring)) getPublicKeyWithLong:keyId] != nil;
}

jboolean LibComAfterlogicPgpUtilNewPGPUtil_keyRingContainsKeyWithIdWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_withLong_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *ring, jlong keyId) {
  LibComAfterlogicPgpUtilNewPGPUtil_initialize();
  return [((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk(ring)) getSecretKeyWithLong:keyId] != nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpUtilNewPGPUtil)
