//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/interfaces/MQVPrivateKey.java
//

#include "J2ObjC_source.h"
#include "MQVPrivateKey.h"

@interface LibOrgBouncycastleJceInterfacesMQVPrivateKey : NSObject

@end

@implementation LibOrgBouncycastleJceInterfacesMQVPrivateKey

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LJavaSecurityPrivateKey;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPublicKey;", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getStaticPrivateKey);
  methods[1].selector = @selector(getEphemeralPrivateKey);
  methods[2].selector = @selector(getEphemeralPublicKey);
  #pragma clang diagnostic pop
  static const J2ObjcClassInfo _LibOrgBouncycastleJceInterfacesMQVPrivateKey = { "MQVPrivateKey", "lib.org.bouncycastle.jce.interfaces", NULL, methods, NULL, 7, 0x609, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceInterfacesMQVPrivateKey;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceInterfacesMQVPrivateKey)