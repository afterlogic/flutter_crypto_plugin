//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/PublicSubkeyPacket.java
//

#include "BCPGInputStream.h"
#include "BCPGKey.h"
#include "BCPGOutputStream.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PacketTags.h"
#include "PublicKeyPacket.h"
#include "PublicSubkeyPacket.h"
#include "java/util/Date.h"

@implementation LibOrgBouncycastleBcpgPublicSubkeyPacket

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGInputStream:(LibOrgBouncycastleBcpgBCPGInputStream *)inArg {
  LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
  return self;
}

- (instancetype)initWithInt:(jint)algorithm
           withJavaUtilDate:(JavaUtilDate *)time
withLibOrgBouncycastleBcpgBCPGKey:(id<LibOrgBouncycastleBcpgBCPGKey>)key {
  LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(self, algorithm, time, key);
  return self;
}

- (void)encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  [((LibOrgBouncycastleBcpgBCPGOutputStream *) nil_chk(outArg)) writePacketWithInt:LibOrgBouncycastleBcpgPacketTags_PUBLIC_SUBKEY withByteArray:[self getEncodedContents] withBoolean:true];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, 1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGInputStream:);
  methods[1].selector = @selector(initWithInt:withJavaUtilDate:withLibOrgBouncycastleBcpgBCPGKey:);
  methods[2].selector = @selector(encodeWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGInputStream;", "LJavaIoIOException;", "ILJavaUtilDate;LLibOrgBouncycastleBcpgBCPGKey;", "encode", "LLibOrgBouncycastleBcpgBCPGOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgPublicSubkeyPacket = { "PublicSubkeyPacket", "lib.org.bouncycastle.bcpg", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgPublicSubkeyPacket;
}

@end

void LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgPublicSubkeyPacket *self, LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  LibOrgBouncycastleBcpgPublicKeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(self, inArg);
}

LibOrgBouncycastleBcpgPublicSubkeyPacket *new_LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgPublicSubkeyPacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

LibOrgBouncycastleBcpgPublicSubkeyPacket *create_LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithLibOrgBouncycastleBcpgBCPGInputStream_(LibOrgBouncycastleBcpgBCPGInputStream *inArg) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgPublicSubkeyPacket, initWithLibOrgBouncycastleBcpgBCPGInputStream_, inArg)
}

void LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(LibOrgBouncycastleBcpgPublicSubkeyPacket *self, jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key) {
  LibOrgBouncycastleBcpgPublicKeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(self, algorithm, time, key);
}

LibOrgBouncycastleBcpgPublicSubkeyPacket *new_LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleBcpgPublicSubkeyPacket, initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_, algorithm, time, key)
}

LibOrgBouncycastleBcpgPublicSubkeyPacket *create_LibOrgBouncycastleBcpgPublicSubkeyPacket_initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_(jint algorithm, JavaUtilDate *time, id<LibOrgBouncycastleBcpgBCPGKey> key) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleBcpgPublicSubkeyPacket, initWithInt_withJavaUtilDate_withLibOrgBouncycastleBcpgBCPGKey_, algorithm, time, key)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgPublicSubkeyPacket)
