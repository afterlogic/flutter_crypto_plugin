//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/bcpg/OutputStreamPacket.java
//

#include "BCPGOutputStream.h"
#include "J2ObjC_source.h"
#include "OutputStreamPacket.h"

@implementation LibOrgBouncycastleBcpgOutputStreamPacket

- (instancetype)initWithLibOrgBouncycastleBcpgBCPGOutputStream:(LibOrgBouncycastleBcpgBCPGOutputStream *)outArg {
  LibOrgBouncycastleBcpgOutputStreamPacket_initWithLibOrgBouncycastleBcpgBCPGOutputStream_(self, outArg);
  return self;
}

- (LibOrgBouncycastleBcpgBCPGOutputStream *)open {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (void)close {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleBcpgBCPGOutputStream;", 0x401, -1, -1, 1, -1, -1, -1 },
    { NULL, "V", 0x401, -1, -1, 1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleBcpgBCPGOutputStream:);
  methods[1].selector = @selector(open);
  methods[2].selector = @selector(close);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "out_", "LLibOrgBouncycastleBcpgBCPGOutputStream;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleBcpgBCPGOutputStream;", "LJavaIoIOException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleBcpgOutputStreamPacket = { "OutputStreamPacket", "lib.org.bouncycastle.bcpg", ptrTable, methods, fields, 7, 0x401, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleBcpgOutputStreamPacket;
}

@end

void LibOrgBouncycastleBcpgOutputStreamPacket_initWithLibOrgBouncycastleBcpgBCPGOutputStream_(LibOrgBouncycastleBcpgOutputStreamPacket *self, LibOrgBouncycastleBcpgBCPGOutputStream *outArg) {
  NSObject_init(self);
  self->out_ = outArg;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleBcpgOutputStreamPacket)