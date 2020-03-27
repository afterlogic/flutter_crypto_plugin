//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPPublicKeyRing.java
//

#include "Arrays.h"
#include "BCPGInputStream.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "KeyFingerPrintCalculator.h"
#include "PGPException.h"
#include "PGPKeyRing.h"
#include "PGPPublicKey.h"
#include "PGPPublicKeyRing.h"
#include "Packet.h"
#include "PacketTags.h"
#include "PublicKeyPacket.h"
#include "TrustPacket.h"
#include "java/io/ByteArrayInputStream.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/lang/Iterable.h"
#include "java/util/ArrayList.h"
#include "java/util/Collections.h"
#include "java/util/Iterator.h"
#include "java/util/List.h"
#include "java/util/Spliterator.h"
#include "java/util/function/Consumer.h"

@interface LibOrgBouncycastleOpenpgpPGPPublicKeyRing ()

+ (id<JavaUtilList>)checkKeysWithJavaUtilList:(id<JavaUtilList>)keys;

@end

__attribute__((unused)) static id<JavaUtilList> LibOrgBouncycastleOpenpgpPGPPublicKeyRing_checkKeysWithJavaUtilList_(id<JavaUtilList> keys);

@implementation LibOrgBouncycastleOpenpgpPGPPublicKeyRing

- (instancetype)initWithByteArray:(IOSByteArray *)encoding
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)fingerPrintCalculator {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(self, encoding, fingerPrintCalculator);
  return self;
}

+ (id<JavaUtilList>)checkKeysWithJavaUtilList:(id<JavaUtilList>)keys {
  return LibOrgBouncycastleOpenpgpPGPPublicKeyRing_checkKeysWithJavaUtilList_(keys);
}

- (instancetype)initWithJavaUtilList:(id<JavaUtilList>)pubKeys {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaUtilList_(self, pubKeys);
  return self;
}

- (instancetype)initWithJavaIoInputStream:(JavaIoInputStream *)inArg
withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)fingerPrintCalculator {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(self, inArg, fingerPrintCalculator);
  return self;
}

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKey {
  return (LibOrgBouncycastleOpenpgpPGPPublicKey *) cast_chk([((id<JavaUtilList>) nil_chk(keys_)) getWithInt:0], [LibOrgBouncycastleOpenpgpPGPPublicKey class]);
}

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKeyWithLong:(jlong)keyID {
  for (jint i = 0; i != [((id<JavaUtilList>) nil_chk(keys_)) size]; i++) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *k = (LibOrgBouncycastleOpenpgpPGPPublicKey *) cast_chk([((id<JavaUtilList>) nil_chk(keys_)) getWithInt:i], [LibOrgBouncycastleOpenpgpPGPPublicKey class]);
    if (keyID == [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(k)) getKeyID]) {
      return k;
    }
  }
  return nil;
}

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKeyWithByteArray:(IOSByteArray *)fingerprint {
  for (jint i = 0; i != [((id<JavaUtilList>) nil_chk(keys_)) size]; i++) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *k = (LibOrgBouncycastleOpenpgpPGPPublicKey *) cast_chk([((id<JavaUtilList>) nil_chk(keys_)) getWithInt:i], [LibOrgBouncycastleOpenpgpPGPPublicKey class]);
    if (LibOrgBouncycastleUtilArrays_areEqualWithByteArray_withByteArray_(fingerprint, [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(k)) getFingerprint])) {
      return k;
    }
  }
  return nil;
}

- (id<JavaUtilIterator>)getKeysWithSignaturesByWithLong:(jlong)keyID {
  id<JavaUtilList> keysWithSigs = new_JavaUtilArrayList_init();
  for (jint i = 0; i != [((id<JavaUtilList>) nil_chk(keys_)) size]; i++) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *k = (LibOrgBouncycastleOpenpgpPGPPublicKey *) cast_chk([((id<JavaUtilList>) nil_chk(keys_)) getWithInt:i], [LibOrgBouncycastleOpenpgpPGPPublicKey class]);
    id<JavaUtilIterator> sigIt = [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(k)) getSignaturesForKeyIDWithLong:keyID];
    if ([((id<JavaUtilIterator>) nil_chk(sigIt)) hasNext]) {
      [keysWithSigs addWithId:k];
    }
  }
  return [keysWithSigs iterator];
}

- (id<JavaUtilIterator>)getPublicKeys {
  return [((id<JavaUtilList>) nil_chk(JavaUtilCollections_unmodifiableListWithJavaUtilList_(keys_))) iterator];
}

- (id<JavaUtilIterator>)iterator {
  return [self getPublicKeys];
}

- (IOSByteArray *)getEncoded {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  [self encodeWithJavaIoOutputStream:bOut];
  return [bOut toByteArray];
}

- (IOSByteArray *)getEncodedWithBoolean:(jboolean)forTransfer {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  [self encodeWithJavaIoOutputStream:bOut withBoolean:forTransfer];
  return [bOut toByteArray];
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream {
  [self encodeWithJavaIoOutputStream:outStream withBoolean:false];
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream
                         withBoolean:(jboolean)forTransfer {
  for (jint i = 0; i != [((id<JavaUtilList>) nil_chk(keys_)) size]; i++) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *k = (LibOrgBouncycastleOpenpgpPGPPublicKey *) cast_chk([((id<JavaUtilList>) nil_chk(keys_)) getWithInt:i], [LibOrgBouncycastleOpenpgpPGPPublicKey class]);
    [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(k)) encodeWithJavaIoOutputStream:outStream withBoolean:forTransfer];
  }
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)insertPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)pubRing
                                                                  withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey {
  return LibOrgBouncycastleOpenpgpPGPPublicKeyRing_insertPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(pubRing, pubKey);
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)removePublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)pubRing
                                                                  withLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey {
  return LibOrgBouncycastleOpenpgpPGPPublicKeyRing_removePublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(pubRing, pubKey);
}

+ (LibOrgBouncycastleOpenpgpPGPPublicKey *)readSubkeyWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg
                                 withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:(id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator>)fingerPrintCalculator {
  return LibOrgBouncycastleOpenpgpPGPPublicKeyRing_readSubkeyWithLibOrgBouncycastleBcpgBCPGInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(inArg, fingerPrintCalculator);
}

- (void)forEachWithJavaUtilFunctionConsumer:(id<JavaUtilFunctionConsumer>)arg0 {
  JavaLangIterable_forEachWithJavaUtilFunctionConsumer_(self, arg0);
}

- (id<JavaUtilSpliterator>)spliterator {
  return JavaLangIterable_spliterator(self);
}

- (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state objects:(__unsafe_unretained id *)stackbuf count:(NSUInteger)len {
  return JreDefaultFastEnumeration(self, state, stackbuf);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, 1, -1, -1, -1 },
    { NULL, "LJavaUtilList;", 0xa, 2, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x1, 5, 6, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x1, 5, 7, -1, -1, -1, -1 },
    { NULL, "LJavaUtilIterator;", 0x1, 8, 6, -1, 9, -1, -1 },
    { NULL, "LJavaUtilIterator;", 0x1, -1, -1, -1, 10, -1, -1 },
    { NULL, "LJavaUtilIterator;", 0x1, -1, -1, -1, 10, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 1, -1, -1, -1 },
    { NULL, "[B", 0x1, 11, 12, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 13, 14, 1, -1, -1, -1 },
    { NULL, "V", 0x1, 13, 15, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", 0x9, 16, 17, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", 0x9, 18, 17, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x8, 19, 20, 21, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:);
  methods[1].selector = @selector(checkKeysWithJavaUtilList:);
  methods[2].selector = @selector(initWithJavaUtilList:);
  methods[3].selector = @selector(initWithJavaIoInputStream:withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:);
  methods[4].selector = @selector(getPublicKey);
  methods[5].selector = @selector(getPublicKeyWithLong:);
  methods[6].selector = @selector(getPublicKeyWithByteArray:);
  methods[7].selector = @selector(getKeysWithSignaturesByWithLong:);
  methods[8].selector = @selector(getPublicKeys);
  methods[9].selector = @selector(iterator);
  methods[10].selector = @selector(getEncoded);
  methods[11].selector = @selector(getEncodedWithBoolean:);
  methods[12].selector = @selector(encodeWithJavaIoOutputStream:);
  methods[13].selector = @selector(encodeWithJavaIoOutputStream:withBoolean:);
  methods[14].selector = @selector(insertPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:withLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[15].selector = @selector(removePublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:withLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[16].selector = @selector(readSubkeyWithLibOrgBouncycastleBcpgBCPGInputStream:withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "keys_", "LJavaUtilList;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[BLLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;", "LJavaIoIOException;", "checkKeys", "LJavaUtilList;", "LJavaIoInputStream;LLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;", "getPublicKey", "J", "[B", "getKeysWithSignaturesBy", "(J)Ljava/util/Iterator<Llib/org/bouncycastle/openpgp/PGPPublicKey;>;", "()Ljava/util/Iterator<Llib/org/bouncycastle/openpgp/PGPPublicKey;>;", "getEncoded", "Z", "encode", "LJavaIoOutputStream;", "LJavaIoOutputStream;Z", "insertPublicKey", "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;LLibOrgBouncycastleOpenpgpPGPPublicKey;", "removePublicKey", "readSubkey", "LLibOrgBouncycastleBcpgBCPGInputStream;LLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator;", "LJavaIoIOException;LLibOrgBouncycastleOpenpgpPGPException;", "Llib/org/bouncycastle/openpgp/PGPKeyRing;Llib/org/bouncycastle/util/Iterable<Llib/org/bouncycastle/openpgp/PGPPublicKey;>;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpPGPPublicKeyRing = { "PGPPublicKeyRing", "lib.org.bouncycastle.openpgp", ptrTable, methods, fields, 7, 0x1, 17, 1, -1, -1, -1, 22, -1 };
  return &_LibOrgBouncycastleOpenpgpPGPPublicKeyRing;
}

@end

void LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *self, IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator) {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(self, new_JavaIoByteArrayInputStream_initWithByteArray_(encoding), fingerPrintCalculator);
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *new_LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPPublicKeyRing, initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_, encoding, fingerPrintCalculator)
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *create_LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(IOSByteArray *encoding, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPPublicKeyRing, initWithByteArray_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_, encoding, fingerPrintCalculator)
}

id<JavaUtilList> LibOrgBouncycastleOpenpgpPGPPublicKeyRing_checkKeysWithJavaUtilList_(id<JavaUtilList> keys) {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initialize();
  id<JavaUtilList> rv = new_JavaUtilArrayList_initWithInt_([((id<JavaUtilList>) nil_chk(keys)) size]);
  for (jint i = 0; i != [keys size]; i++) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *k = (LibOrgBouncycastleOpenpgpPGPPublicKey *) cast_chk([keys getWithInt:i], [LibOrgBouncycastleOpenpgpPGPPublicKey class]);
    if (i == 0) {
      if (![((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(k)) isMasterKey]) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"key 0 must be a master key");
      }
    }
    else {
      if ([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(k)) isMasterKey]) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"key 0 can be only master key");
      }
    }
    [rv addWithId:k];
  }
  return rv;
}

void LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaUtilList_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *self, id<JavaUtilList> pubKeys) {
  LibOrgBouncycastleOpenpgpPGPKeyRing_init(self);
  self->keys_ = LibOrgBouncycastleOpenpgpPGPPublicKeyRing_checkKeysWithJavaUtilList_(pubKeys);
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *new_LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaUtilList_(id<JavaUtilList> pubKeys) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPPublicKeyRing, initWithJavaUtilList_, pubKeys)
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *create_LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaUtilList_(id<JavaUtilList> pubKeys) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPPublicKeyRing, initWithJavaUtilList_, pubKeys)
}

void LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *self, JavaIoInputStream *inArg, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator) {
  LibOrgBouncycastleOpenpgpPGPKeyRing_init(self);
  self->keys_ = new_JavaUtilArrayList_init();
  LibOrgBouncycastleBcpgBCPGInputStream *pIn = LibOrgBouncycastleOpenpgpPGPKeyRing_wrapWithJavaIoInputStream_(inArg);
  jint initialTag = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(pIn)) nextPacketTag];
  if (initialTag != LibOrgBouncycastleBcpgPacketTags_PUBLIC_KEY && initialTag != LibOrgBouncycastleBcpgPacketTags_PUBLIC_SUBKEY) {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$$", @"public key ring doesn't start with public key tag: tag 0x", JavaLangInteger_toHexStringWithInt_(initialTag)));
  }
  LibOrgBouncycastleBcpgPublicKeyPacket *pubPk = (LibOrgBouncycastleBcpgPublicKeyPacket *) cast_chk([pIn readPacket], [LibOrgBouncycastleBcpgPublicKeyPacket class]);
  LibOrgBouncycastleBcpgTrustPacket *trustPk = LibOrgBouncycastleOpenpgpPGPKeyRing_readOptionalTrustPacketWithLibOrgBouncycastleBcpgBCPGInputStream_(pIn);
  id<JavaUtilList> keySigs = LibOrgBouncycastleOpenpgpPGPKeyRing_readSignaturesAndTrustWithLibOrgBouncycastleBcpgBCPGInputStream_(pIn);
  id<JavaUtilList> ids = new_JavaUtilArrayList_init();
  id<JavaUtilList> idTrusts = new_JavaUtilArrayList_init();
  id<JavaUtilList> idSigs = new_JavaUtilArrayList_init();
  LibOrgBouncycastleOpenpgpPGPKeyRing_readUserIDsWithLibOrgBouncycastleBcpgBCPGInputStream_withJavaUtilList_withJavaUtilList_withJavaUtilList_(pIn, ids, idTrusts, idSigs);
  @try {
    [((id<JavaUtilList>) nil_chk(self->keys_)) addWithId:new_LibOrgBouncycastleOpenpgpPGPPublicKey_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withLibOrgBouncycastleBcpgTrustPacket_withJavaUtilList_withJavaUtilList_withJavaUtilList_withJavaUtilList_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(pubPk, trustPk, keySigs, ids, idTrusts, idSigs, fingerPrintCalculator)];
    while ([pIn nextPacketTag] == LibOrgBouncycastleBcpgPacketTags_PUBLIC_SUBKEY) {
      [((id<JavaUtilList>) nil_chk(self->keys_)) addWithId:LibOrgBouncycastleOpenpgpPGPPublicKeyRing_readSubkeyWithLibOrgBouncycastleBcpgBCPGInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(pIn, fingerPrintCalculator)];
    }
  }
  @catch (LibOrgBouncycastleOpenpgpPGPException *e) {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$$", @"processing exception: ", [e description]));
  }
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *new_LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(JavaIoInputStream *inArg, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPPublicKeyRing, initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_, inArg, fingerPrintCalculator)
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *create_LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(JavaIoInputStream *inArg, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPPublicKeyRing, initWithJavaIoInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_, inArg, fingerPrintCalculator)
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *LibOrgBouncycastleOpenpgpPGPPublicKeyRing_insertPublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *pubRing, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey) {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initialize();
  id<JavaUtilList> keys = new_JavaUtilArrayList_initWithJavaUtilCollection_(((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk(pubRing))->keys_);
  jboolean found = false;
  jboolean masterFound = false;
  for (jint i = 0; i != [keys size]; i++) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *key = (LibOrgBouncycastleOpenpgpPGPPublicKey *) cast_chk([keys getWithInt:i], [LibOrgBouncycastleOpenpgpPGPPublicKey class]);
    if ([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(key)) getKeyID] == [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(pubKey)) getKeyID]) {
      found = true;
      (void) [keys setWithInt:i withId:pubKey];
    }
    if ([key isMasterKey]) {
      masterFound = true;
    }
  }
  if (!found) {
    if ([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(pubKey)) isMasterKey]) {
      if (masterFound) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"cannot add a master key to a ring that already has one");
      }
      [keys addWithInt:0 withId:pubKey];
    }
    else {
      [keys addWithId:pubKey];
    }
  }
  return new_LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaUtilList_(keys);
}

LibOrgBouncycastleOpenpgpPGPPublicKeyRing *LibOrgBouncycastleOpenpgpPGPPublicKeyRing_removePublicKeyWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_withLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *pubRing, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey) {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initialize();
  id<JavaUtilList> keys = new_JavaUtilArrayList_initWithJavaUtilCollection_(((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk(pubRing))->keys_);
  jboolean found = false;
  for (jint i = 0; i < [keys size]; i++) {
    LibOrgBouncycastleOpenpgpPGPPublicKey *key = (LibOrgBouncycastleOpenpgpPGPPublicKey *) cast_chk([keys getWithInt:i], [LibOrgBouncycastleOpenpgpPGPPublicKey class]);
    if ([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(key)) getKeyID] == [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(pubKey)) getKeyID]) {
      found = true;
      (void) [keys removeWithInt:i];
    }
  }
  if (!found) {
    return nil;
  }
  return new_LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initWithJavaUtilList_(keys);
}

LibOrgBouncycastleOpenpgpPGPPublicKey *LibOrgBouncycastleOpenpgpPGPPublicKeyRing_readSubkeyWithLibOrgBouncycastleBcpgBCPGInputStream_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(LibOrgBouncycastleBcpgBCPGInputStream *inArg, id<LibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator> fingerPrintCalculator) {
  LibOrgBouncycastleOpenpgpPGPPublicKeyRing_initialize();
  LibOrgBouncycastleBcpgPublicKeyPacket *pk = (LibOrgBouncycastleBcpgPublicKeyPacket *) cast_chk([((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(inArg)) readPacket], [LibOrgBouncycastleBcpgPublicKeyPacket class]);
  LibOrgBouncycastleBcpgTrustPacket *kTrust = LibOrgBouncycastleOpenpgpPGPKeyRing_readOptionalTrustPacketWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
  id<JavaUtilList> sigList = LibOrgBouncycastleOpenpgpPGPKeyRing_readSignaturesAndTrustWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg);
  return new_LibOrgBouncycastleOpenpgpPGPPublicKey_initWithLibOrgBouncycastleBcpgPublicKeyPacket_withLibOrgBouncycastleBcpgTrustPacket_withJavaUtilList_withLibOrgBouncycastleOpenpgpOperatorKeyFingerPrintCalculator_(pk, kTrust, sigList, fingerPrintCalculator);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpPGPPublicKeyRing)
