//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/operator/jcajce/JcaPGPPrivateKey.java
//

#include "J2ObjC_source.h"
#include "JcaPGPPrivateKey.h"
#include "PGPPrivateKey.h"
#include "PGPPublicKey.h"
#include "PublicKeyPacket.h"
#include "java/security/PrivateKey.h"

@interface LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey () {
 @public
  id<JavaSecurityPrivateKey> privateKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey, privateKey_, id<JavaSecurityPrivateKey>)

@implementation LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey

- (instancetype)initWithLong:(jlong)keyID
  withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey_initWithLong_withJavaSecurityPrivateKey_(self, keyID, privateKey);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pubKey
                                   withJavaSecurityPrivateKey:(id<JavaSecurityPrivateKey>)privateKey {
  LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_(self, pubKey, privateKey);
  return self;
}

- (id<JavaSecurityPrivateKey>)getPrivateKey {
  return privateKey_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityPrivateKey;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLong:withJavaSecurityPrivateKey:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPPublicKey:withJavaSecurityPrivateKey:);
  methods[2].selector = @selector(getPrivateKey);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "privateKey_", "LJavaSecurityPrivateKey;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "JLJavaSecurityPrivateKey;", "LLibOrgBouncycastleOpenpgpPGPPublicKey;LJavaSecurityPrivateKey;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey = { "JcaPGPPrivateKey", "lib.org.bouncycastle.openpgp.operator.jcajce", ptrTable, methods, fields, 7, 0x1, 3, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey;
}

@end

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey_initWithLong_withJavaSecurityPrivateKey_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey *self, jlong keyID, id<JavaSecurityPrivateKey> privateKey) {
  LibOrgBouncycastleOpenpgpPGPPrivateKey_initWithLong_withLibOrgBouncycastleBcpgPublicKeyPacket_withLibOrgBouncycastleBcpgBCPGKey_(self, keyID, nil, nil);
  self->privateKey_ = privateKey;
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey_initWithLong_withJavaSecurityPrivateKey_(jlong keyID, id<JavaSecurityPrivateKey> privateKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey, initWithLong_withJavaSecurityPrivateKey_, keyID, privateKey)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey_initWithLong_withJavaSecurityPrivateKey_(jlong keyID, id<JavaSecurityPrivateKey> privateKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey, initWithLong_withJavaSecurityPrivateKey_, keyID, privateKey)
}

void LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey *self, LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey, id<JavaSecurityPrivateKey> privateKey) {
  LibOrgBouncycastleOpenpgpPGPPrivateKey_initWithLong_withLibOrgBouncycastleBcpgPublicKeyPacket_withLibOrgBouncycastleBcpgBCPGKey_(self, [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(pubKey)) getKeyID], [pubKey getPublicKeyPacket], nil);
  self->privateKey_ = privateKey;
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey *new_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_(LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey, id<JavaSecurityPrivateKey> privateKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey, initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_, pubKey, privateKey)
}

LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey *create_LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_(LibOrgBouncycastleOpenpgpPGPPublicKey *pubKey, id<JavaSecurityPrivateKey> privateKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey, initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withJavaSecurityPrivateKey_, pubKey, privateKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpOperatorJcajceJcaPGPPrivateKey)