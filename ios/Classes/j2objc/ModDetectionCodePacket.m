//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/ModDetectionCodePacket.java
//

#include "BCPGInputStream.h"
#include "BCPGOutputStream.h"
#include "ContainedPacket.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ModDetectionCodePacket.h"
#include "PacketTags.h"
#include "java/lang/System.h"

@interface LibOrgBouncycastleBcpgModDetectionCodePacket () {
 @public
  IOSByteArray *digest_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleBcpgModDetectionCodePacket, digest_, IOSByteArray *)

@implementation LibOrgBouncycastleBcpgModDetectionCodePacket

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgModDetectionCodePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)digest {
  LibOrgBouncycastleBcpgModDetectionCodePacket_initWithByteArray_(self, digest);
  return self;
}

- (IOSByteArray *)getDigest {
  IOSByteArray *tmp = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(digest_))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(digest_, 0, tmp, 0, tmp->size_);
  return tmp;
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writePacketWithInt:LibOrgBouncycastleBcpgPacketTags_MOD_DETECTION_CODE withByteArray:digest_ withBoolean:false];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, 1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithByteArray:);
  methods[2].selector = @selector(getDigest);
  methods[3].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "digest_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "[B", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgModDetectionCodePacket = { "ModDetectionCodePacket", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgModDetectionCodePacket;
}

@end

void LibOrgBouncycastleBcpgModDetectionCodePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgModDetectionCodePacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->digest_ = [IOSByteArray newArrayWithLength:20];
  [((LibOrgBouncycastleBcpgBCPGInputStream *) nil_chk(inArg)) readFullyWithByteArray:self->digest_];
}

LibOrgBouncycastleBcpgModDetectionCodePacket *new_LibOrgBouncycastleBcpgModDetectionCodePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgModDetectionCodePacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

LibOrgBouncycastleBcpgModDetectionCodePacket *create_LibOrgBouncycastleBcpgModDetectionCodePacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgModDetectionCodePacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

void LibOrgBouncycastleBcpgModDetectionCodePacket_initWithByteArray_(LibOrgBouncycastleBcpgModDetectionCodePacket *self, IOSByteArray *digest) {
  LibOrgBouncycastleBcpgContainedPacket_init(self);
  self->digest_ = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(digest))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(digest, 0, self->digest_, 0, self->digest_->size_);
}

LibOrgBouncycastleBcpgModDetectionCodePacket *new_LibOrgBouncycastleBcpgModDetectionCodePacket_initWithByteArray_(IOSByteArray *digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgModDetectionCodePacket, initWithByteArray_, digest)
}

LibOrgBouncycastleBcpgModDetectionCodePacket *create_LibOrgBouncycastleBcpgModDetectionCodePacket_initWithByteArray_(IOSByteArray *digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgModDetectionCodePacket, initWithByteArray_, digest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgModDetectionCodePacket)
