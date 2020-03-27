//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPKeyRing.java
//

#include "BCPGInputStream.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PGPException.h"
#include "PGPKeyRing.h"
#include "PGPPublicKey.h"
#include "PGPSignature.h"
#include "PGPUserAttributeSubpacketVector.h"
#include "Packet.h"
#include "PacketTags.h"
#include "SignaturePacket.h"
#include "TrustPacket.h"
#include "UserAttributePacket.h"
#include "UserIDPacket.h"
#include "java/io/IOException.h"
#include "java/io/InputStream.h"
#include "java/io/OutputStream.h"
#include "java/lang/Exception.h"
#include "java/util/ArrayList.h"
#include "java/util/Iterator.h"
#include "java/util/List.h"

@implementation LibOrgBouncycastleOpenpgpPGPKeyRing

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleOpenpgpPGPKeyRing_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleBcpgBCPGInputStream *)wrapWithJavaIoInputStream:(JavaIoInputStream *)inArg {
  return LibOrgBouncycastleOpenpgpPGPKeyRing_wrapWithJavaIoInputStream_(inArg);
}

+ (LibOrgBouncycastleBcpgTrustPacket *)readOptionalTrustPacketWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)pIn {
  return LibOrgBouncycastleOpenpgpPGPKeyRing_readOptionalTrustPacketWithLibOrgBouncycastleBcpgBCPGInputStream_(pIn);
}

+ (id<JavaUtilList>)readSignaturesAndTrustWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)pIn {
  return LibOrgBouncycastleOpenpgpPGPKeyRing_readSignaturesAndTrustWithLibOrgBouncycastleBcpgBCPGInputStream_(pIn);
}

+ (void)readUserIDsWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)pIn
                                            withJavaUtilList:(id<JavaUtilList>)ids
                                            withJavaUtilList:(id<JavaUtilList>)idTrusts
                                            withJavaUtilList:(id<JavaUtilList>)idSigs {
  LibOrgBouncycastleOpenpgpPGPKeyRing_readUserIDsWithLibOrgBouncycastleBcpgBCPGInputStream_withJavaUtilList_withJavaUtilList_withJavaUtilList_(pIn, ids, idTrusts, idSigs);
}

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKey {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (id<JavaUtilIterator>)getPublicKeys {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKeyWithLong:(jlong)keyID {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKeyWithByteArray:(IOSByteArray *)fingerprint {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (id<JavaUtilIterator>)getKeysWithSignaturesByWithLong:(jlong)keyID {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)outStream {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

- (IOSByteArray *)getEncoded {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleBcpgBCPGInputStream;", 0x8, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleBcpgTrustPacket;", 0x8, 2, 3, 4, -1, -1, -1 },
    { NULL, "LJavaUtilList;", 0x8, 5, 3, 4, -1, -1, -1 },
    { NULL, "V", 0x8, 6, 7, 4, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilIterator;", 0x401, -1, -1, -1, 8, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x401, 9, 10, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x401, 9, 11, -1, -1, -1, -1 },
    { NULL, "LJavaUtilIterator;", 0x401, 12, 10, -1, 13, -1, -1 },
    { NULL, "V", 0x401, 14, 15, 4, -1, -1, -1 },
    { NULL, "[B", 0x401, -1, -1, 4, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(wrapWithJavaIoInputStream:);
  methods[2].selector = @selector(readOptionalTrustPacketWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[3].selector = @selector(readSignaturesAndTrustWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[4].selector = @selector(readUserIDsWithLibOrgBouncycastleBcpgBCPGInputStream:withJavaUtilList:withJavaUtilList:withJavaUtilList:);
  methods[5].selector = @selector(getPublicKey);
  methods[6].selector = @selector(getPublicKeys);
  methods[7].selector = @selector(getPublicKeyWithLong:);
  methods[8].selector = @selector(getPublicKeyWithByteArray:);
  methods[9].selector = @selector(getKeysWithSignaturesByWithLong:);
  methods[10].selector = @selector(encodeWithJavaIoOutputStream:);
  methods[11].selector = @selector(getEncoded);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "wrap", "LJavaIoInputStream;", "readOptionalTrustPacket", "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "readSignaturesAndTrust", "readUserIDs", "LLibOrgBouncycastleBcpgBCPGInputStream;LJavaUtilList;LJavaUtilList;LJavaUtilList;", "()Ljava/util/Iterator<Llib/org/bouncycastle/openpgp/PGPPublicKey;>;", "getPublicKey", "J", "[B", "getKeysWithSignaturesBy", "(J)Ljava/util/Iterator<Llib/org/bouncycastle/openpgp/PGPPublicKey;>;", "encode", "LJavaIoOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpPGPKeyRing = { "PGPKeyRing", "lib.org.bouncycastle.openpgp", ptrTable, methods, NULL, 7, 0x401, 12, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpPGPKeyRing;
}

@end

void LibOrgBouncycastleOpenpgpPGPKeyRing_init(LibOrgBouncycastleOpenpgpPGPKeyRing *self) {
  NSObject_init(self);
}

LibOrgBouncycastleBcpgBCPGInputStream *LibOrgBouncycastleOpenpgpPGPKeyRing_wrapWithJavaIoInputStream_(JavaIoInputStream *inArg) {
  LibOrgBouncycastleOpenpgpPGPKeyRing_initialize();
  if ([inArg isKindOfClass:[LibOrgBouncycastleBcpgBCPGInputStream class]]) {
    return (LibOrgBouncycastleBcpgBCPGInputStream *) inArg;
  }
  return new_LibOrgBouncycastleBcpgBCPGInputStream_initWithJavaIoInputStream_(inArg);
}

LibOrgBouncycastleBcpgTrustPacket *LibOrgBouncycastleOpenpgpPGPKeyRing_readOptionalTrustPacketWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *pIn) {
  LibOrgBouncycastleOpenpgpPGPKeyRing_initialize();
  return ([((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(pIn)) nextPacketTag] == LibOrgBouncycastleBcpgPacketTags_TRUST) ? (LibOrgBouncycastleBcpgTrustPacket *) cast_chk([pIn readPacket], [LibOrgBouncycastleBcpgTrustPacket class]) : nil;
}

id<JavaUtilList> LibOrgBouncycastleOpenpgpPGPKeyRing_readSignaturesAndTrustWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *pIn) {
  LibOrgBouncycastleOpenpgpPGPKeyRing_initialize();
  @try {
    id<JavaUtilList> sigList = new_JavaUtilArrayList_init();
    while ([((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(pIn)) nextPacketTag] == LibOrgBouncycastleBcpgPacketTags_SIGNATURE) {
      LibOrgBouncycastleBcpgSignaturePacket *signaturePacket = (LibOrgBouncycastleBcpgSignaturePacket *) cast_chk([pIn readPacket], [LibOrgBouncycastleBcpgSignaturePacket class]);
      LibOrgBouncycastleBcpgTrustPacket *trustPacket = LibOrgBouncycastleOpenpgpPGPKeyRing_readOptionalTrustPacketWithLibOrgBouncycastleBcpgBCPGInputStream_(pIn);
      [sigList addWithId:new_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_withLibOrgBouncycastleBcpgTrustPacket_(signaturePacket, trustPacket)];
    }
    return sigList;
  }
  @catch (LibOrgBouncycastleOpenpgpPGPException *e) {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$$$$", @"can't create signature object: ", [e getMessage], @", cause: ", [((JavaLangException *) nil_chk([e getUnderlyingException])) description]));
  }
}

void LibOrgBouncycastleOpenpgpPGPKeyRing_readUserIDsWithLibOrgBouncycastleBcpgBCPGInputStream_withJavaUtilList_withJavaUtilList_withJavaUtilList_(LibOrgBouncycastleBcpgBCPGInputStream *pIn, id<JavaUtilList> ids, id<JavaUtilList> idTrusts, id<JavaUtilList> idSigs) {
  LibOrgBouncycastleOpenpgpPGPKeyRing_initialize();
  while ([((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(pIn)) nextPacketTag] == LibOrgBouncycastleBcpgPacketTags_USER_ID || [pIn nextPacketTag] == LibOrgBouncycastleBcpgPacketTags_USER_ATTRIBUTE) {
    LibOrgBouncycastleBcpgPacket *obj = [pIn readPacket];
    if ([obj isKindOfClass:[LibOrgBouncycastleBcpgUserIDPacket class]]) {
      LibOrgBouncycastleBcpgUserIDPacket *id_ = (LibOrgBouncycastleBcpgUserIDPacket *) obj;
      [((id<JavaUtilList>) nil_chk(ids)) addWithId:id_];
    }
    else {
      LibOrgBouncycastleBcpgUserAttributePacket *user = (LibOrgBouncycastleBcpgUserAttributePacket *) cast_chk(obj, [LibOrgBouncycastleBcpgUserAttributePacket class]);
      [((id<JavaUtilList>) nil_chk(ids)) addWithId:new_LibOrgBouncycastleOpenpgpPGPUserAttributeSubpacketVector_initWithLibOrgBouncycastleBcpgUserAttributeSubpacketArray_([((LibOrgBouncycastleBcpgUserAttributePacket *) nil_chk(user)) getSubpackets])];
    }
    [((id<JavaUtilList>) nil_chk(idTrusts)) addWithId:LibOrgBouncycastleOpenpgpPGPKeyRing_readOptionalTrustPacketWithLibOrgBouncycastleBcpgBCPGInputStream_(pIn)];
    [((id<JavaUtilList>) nil_chk(idSigs)) addWithId:LibOrgBouncycastleOpenpgpPGPKeyRing_readSignaturesAndTrustWithLibOrgBouncycastleBcpgBCPGInputStream_(pIn)];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpPGPKeyRing)
