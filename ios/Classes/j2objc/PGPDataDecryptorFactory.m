//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/PGPDataDecryptorFactory.java
//

#include "J2ObjC_source.h"
#include "PGPDataDecryptorFactory.h"

@interface LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptorFactory : NSObject

@end

@implementation LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptorFactory

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleOpenpgpOperatorPGPDataDecryptor;", 0x401, 0, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(createDataDecryptorWithBoolean:withInt:withByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "createDataDecryptor", "ZI[B", "LLibOrgBouncycastleOpenpgpPGPException;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptorFactory = { "PGPDataDecryptorFactory", "lib.org.bouncycastle.openpgp.operator", ptrTable, methods, NULL, 7, 0x609, 1, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptorFactory;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorPGPDataDecryptorFactory)
