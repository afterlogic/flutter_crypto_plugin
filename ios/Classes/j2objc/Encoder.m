//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/encoders/Encoder.java
//

#include "Encoder.h"
#include "J2ObjC_source.h"

@interface LibOrgBouncycastleUtilEncodersEncoder : NSObject

@end

@implementation LibOrgBouncycastleUtilEncodersEncoder

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "I", 0x401, 0, 1, 2, -1, -1, -1 },
    { NULL, "I", 0x401, 3, 1, 2, -1, -1, -1 },
    { NULL, "I", 0x401, 3, 4, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(encodeWithByteArray:withInt:withInt:withJavaIoOutputStream:);
  methods[1].selector = @selector(decodeWithByteArray:withInt:withInt:withJavaIoOutputStream:);
  methods[2].selector = @selector(decodeWithNSString:withJavaIoOutputStream:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "encode", "[BIILJavaIoOutputStream;", "LJavaIoIOException;", "decode", "LNSString;LJavaIoOutputStream;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilEncodersEncoder = { "Encoder", "lib.org.bouncycastle.util.encoders", ptrTable, methods, NULL, 7, 0x609, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilEncodersEncoder;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilEncodersEncoder)
