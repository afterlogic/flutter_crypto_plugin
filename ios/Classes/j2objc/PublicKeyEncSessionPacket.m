//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/PublicKeyEncSessionPacket.java
//

#include "Arrays.h"
#include "BCPGInputStream.h"
#include "BCPGOutputStream.h"
#include "ContainedPacket.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MPInteger.h"
#include "PacketTags.h"
#include "PublicKeyAlgorithmTags.h"
#include "PublicKeyEncSessionPacket.h"
#include "Streams.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"

@interface LibOrgBouncycastleBcpgPublicKeyEncSessionPacket () {
 @public
  jint version__;
  jlong keyID_;
  jint algorithm_;
  IOSObjectArray *data_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket, data_, IOSObjectArray *)

@implementation LibOrgBouncycastleBcpgPublicKeyEncSessionPacket

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgPublicKeyEncSessionPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithLong:(jlong)keyID
                     withInt:(jint)algorithm
              withByteArray2:(IOSObjectArray *)data {
  LibOrgBouncycastleBcpgPublicKeyEncSessionPacket_initWithLong_withInt_withByteArray2_(self, keyID, algorithm, data);
  return self;
}

- (jint)getVersion {
  return version__;
}

- (jlong)getKeyID {
  return keyID_;
}

- (jint)getAlgorithm {
  return algorithm_;
}

- (IOSObjectArray *)getEncSessionKey {
  return data_;
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleBcpgBCPGOutputStream *pOut = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(bOut);
  [pOut writeWithInt:version__];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 56))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 48))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 40))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 32))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 24))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 16))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 8))];
  [pOut writeWithInt:(jbyte) (keyID_)];
  [pOut writeWithInt:algorithm_];
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(data_))->size_; i++) {
    [pOut writeWithByteArray:IOSObjectArray_Get(data_, i)];
  }
  [pOut close];
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writePacketWithInt:LibOrgBouncycastleBcpgPacketTags_PUBLIC_KEY_ENC_SESSION withByteArray:[bOut toByteArray] withBoolean:true];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithLong:withInt:withByteArray2:);
  methods[2].selector = @selector(getVersion);
  methods[3].selector = @selector(getKeyID);
  methods[4].selector = @selector(getAlgorithm);
  methods[5].selector = @selector(getEncSessionKey);
  methods[6].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "I", .constantValue.asLong = 0, 0x2, 5, -1, -1, -1 },
    { "keyID_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "algorithm_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "data_", "[[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "JI[[B", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgPublicKeyEncSessionPacket = { "PublicKeyEncSessionPacket", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 7, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgPublicKeyEncSessionPacket;
}

@end

void LibOrgBouncycastleBcpgPublicKeyEncSessionPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->version__ = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(inArg)) read];
  self->keyID_ |= JreLShift64((jlong) [inArg read], 56);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 48);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 40);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 32);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 24);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 16);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 8);
  self->keyID_ |= [inArg read];
  self->algorithm_ = [inArg read];
  switch (self->algorithm_) {
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_ENCRYPT:
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL:
    self->data_ = [IOSObjectArray newArrayWithLength:1 type:IOSClass_byteArray(1)];
    (void) IOSObjectArray_Set(self->data_, 0, [new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg) getEncoded]);
    break;
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_ENCRYPT:
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ELGAMAL_GENERAL:
    self->data_ = [IOSObjectArray newArrayWithLength:2 type:IOSClass_byteArray(1)];
    (void) IOSObjectArray_Set(self->data_, 0, [new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg) getEncoded]);
    (void) IOSObjectArray_Set(nil_chk(self->data_), 1, [new_LibOrgBouncycastleBcpgMPInteger_initWithLibOrgBouncycastleBcpgBCPGInputStream_(inArg) getEncoded]);
    break;
    case LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_ECDH:
    self->data_ = [IOSObjectArray newArrayWithLength:1 type:IOSClass_byteArray(1)];
    (void) IOSObjectArray_Set(self->data_, 0, LibOrgBouncycastleUtilIoStreams_readAllWithJavaIoInputStream_(inArg));
    break;
    default:
    @throw new_JavaIoIOException_initWithNSString_(@"unknown PGP public key algorithm encountered");
  }
}

LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *new_LibOrgBouncycastleBcpgPublicKeyEncSessionPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *create_LibOrgBouncycastleBcpgPublicKeyEncSessionPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

void LibOrgBouncycastleBcpgPublicKeyEncSessionPacket_initWithLong_withInt_withByteArray2_(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *self, jlong keyID, jint algorithm, IOSObjectArray *data) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->version__ = 3;
  self->keyID_ = keyID;
  self->algorithm_ = algorithm;
  self->data_ = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(data))->size_ type:IOSClass_byteArray(1)];
  for (jint i = 0; i != data->size_; i++) {
    (void) IOSObjectArray_Set(nil_chk(self->data_), i, LibOrgBouncycastleUtilArrays_cloneWithByteArray_(IOSObjectArray_Get(data, i)));
  }
}

LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *new_LibOrgBouncycastleBcpgPublicKeyEncSessionPacket_initWithLong_withInt_withByteArray2_(jlong keyID, jint algorithm, IOSObjectArray *data) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket, initWithLong_withInt_withByteArray2_, keyID, algorithm, data)
}

LibOrgBouncycastleBcpgPublicKeyEncSessionPacket *create_LibOrgBouncycastleBcpgPublicKeyEncSessionPacket_initWithLong_withInt_withByteArray2_(jlong keyID, jint algorithm, IOSObjectArray *data) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket, initWithLong_withInt_withByteArray2_, keyID, algorithm, data)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgPublicKeyEncSessionPacket)
