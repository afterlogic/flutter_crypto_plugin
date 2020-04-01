//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/OnePassSignaturePacket.java
//

#include "BCPGInputStream.h"
#include "BCPGOutputStream.h"
#include "ContainedPacket.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OnePassSignaturePacket.h"
#include "PacketTags.h"
#include "java/io/ByteArrayOutputStream.h"

@interface LibOrgBouncycastleBcpgOnePassSignaturePacket () {
 @public
  jint version__;
  jint sigType_;
  jint hashAlgorithm_;
  jint keyAlgorithm_;
  jlong keyID_;
  jint nested_;
}

@end

@implementation LibOrgBouncycastleBcpgOnePassSignaturePacket

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgOnePassSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithInt:(jint)sigType
                    withInt:(jint)hashAlgorithm
                    withInt:(jint)keyAlgorithm
                   withLong:(jlong)keyID
                withBoolean:(jboolean)isNested {
  LibOrgBouncycastleBcpgOnePassSignaturePacket_initWithInt_withInt_withInt_withLong_withBoolean_(self, sigType, hashAlgorithm, keyAlgorithm, keyID, isNested);
  return self;
}

- (jint)getSignatureType {
  return sigType_;
}

- (jint)getKeyAlgorithm {
  return keyAlgorithm_;
}

- (jint)getHashAlgorithm {
  return hashAlgorithm_;
}

- (jlong)getKeyID {
  return keyID_;
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  JavaIoByteArrayOutputStream *bOut = new_JavaIoByteArrayOutputStream_init();
  LibOrgBouncycastleBcpgBCPGOutputStream *pOut = new_LibOrgBouncycastleBcpgBCPGOutputStream_initWithJavaIoOutputStream_(bOut);
  [pOut writeWithInt:version__];
  [pOut writeWithInt:sigType_];
  [pOut writeWithInt:hashAlgorithm_];
  [pOut writeWithInt:keyAlgorithm_];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 56))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 48))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 40))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 32))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 24))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 16))];
  [pOut writeWithInt:(jbyte) (JreRShift64(keyID_, 8))];
  [pOut writeWithInt:(jbyte) (keyID_)];
  [pOut writeWithInt:nested_];
  [pOut close];
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writePacketWithInt:LibOrgBouncycastleBcpgPacketTags_ONE_PASS_SIGNATURE withByteArray:[bOut toByteArray] withBoolean:true];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithInt:withInt:withInt:withLong:withBoolean:);
  methods[2].selector = @selector(getSignatureType);
  methods[3].selector = @selector(getKeyAlgorithm);
  methods[4].selector = @selector(getHashAlgorithm);
  methods[5].selector = @selector(getKeyID);
  methods[6].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "version__", "I", .constantValue.asLong = 0, 0x2, 5, -1, -1, -1 },
    { "sigType_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashAlgorithm_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyAlgorithm_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "keyID_", "J", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "nested_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "IIIJZ", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;", "version" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgOnePassSignaturePacket = { "OnePassSignaturePacket", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 7, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgOnePassSignaturePacket;
}

@end

void LibOrgBouncycastleBcpgOnePassSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgOnePassSignaturePacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->version__ = [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(inArg)) read];
  self->sigType_ = [inArg read];
  self->hashAlgorithm_ = [inArg read];
  self->keyAlgorithm_ = [inArg read];
  self->keyID_ |= JreLShift64((jlong) [inArg read], 56);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 48);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 40);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 32);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 24);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 16);
  self->keyID_ |= JreLShift64((jlong) [inArg read], 8);
  self->keyID_ |= [inArg read];
  self->nested_ = [inArg read];
}

LibOrgBouncycastleBcpgOnePassSignaturePacket *new_LibOrgBouncycastleBcpgOnePassSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgOnePassSignaturePacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

LibOrgBouncycastleBcpgOnePassSignaturePacket *create_LibOrgBouncycastleBcpgOnePassSignaturePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgOnePassSignaturePacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

void LibOrgBouncycastleBcpgOnePassSignaturePacket_initWithInt_withInt_withInt_withLong_withBoolean_(LibOrgBouncycastleBcpgOnePassSignaturePacket *self, jint sigType, jint hashAlgorithm, jint keyAlgorithm, jlong keyID, jboolean isNested) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->version__ = 3;
  self->sigType_ = sigType;
  self->hashAlgorithm_ = hashAlgorithm;
  self->keyAlgorithm_ = keyAlgorithm;
  self->keyID_ = keyID;
  self->nested_ = (isNested) ? 0 : 1;
}

LibOrgBouncycastleBcpgOnePassSignaturePacket *new_LibOrgBouncycastleBcpgOnePassSignaturePacket_initWithInt_withInt_withInt_withLong_withBoolean_(jint sigType, jint hashAlgorithm, jint keyAlgorithm, jlong keyID, jboolean isNested) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgOnePassSignaturePacket, initWithInt_withInt_withInt_withLong_withBoolean_, sigType, hashAlgorithm, keyAlgorithm, keyID, isNested)
}

LibOrgBouncycastleBcpgOnePassSignaturePacket *create_LibOrgBouncycastleBcpgOnePassSignaturePacket_initWithInt_withInt_withInt_withLong_withBoolean_(jint sigType, jint hashAlgorithm, jint keyAlgorithm, jlong keyID, jboolean isNested) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgOnePassSignaturePacket, initWithInt_withInt_withInt_withLong_withBoolean_, sigType, hashAlgorithm, keyAlgorithm, keyID, isNested)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgOnePassSignaturePacket)