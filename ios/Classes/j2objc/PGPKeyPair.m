//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPKeyPair.java
//

#include "J2ObjC_source.h"
#include "PGPKeyPair.h"
#include "PGPPrivateKey.h"
#include "PGPPublicKey.h"

@implementation LibOrgBouncycastleOpenpgpPGPKeyPair

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)pub
                   withLibOrgBouncycastleOpenpgpPGPPrivateKey:(LibOrgBouncycastleOpenpgpPGPPrivateKey *)priv {
  LibOrgBouncycastleOpenpgpPGPKeyPair_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpPGPPrivateKey_(self, pub, priv);
  return self;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleOpenpgpPGPKeyPair_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jlong)getKeyID {
  return [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(pub_)) getKeyID];
}

- (LibOrgBouncycastleOpenpgpPGPPublicKey *)getPublicKey {
  return pub_;
}

- (LibOrgBouncycastleOpenpgpPGPPrivateKey *)getPrivateKey {
  return priv_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPublicKey;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPPrivateKey;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPPublicKey:withLibOrgBouncycastleOpenpgpPGPPrivateKey:);
  methods[1].selector = @selector(init);
  methods[2].selector = @selector(getKeyID);
  methods[3].selector = @selector(getPublicKey);
  methods[4].selector = @selector(getPrivateKey);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "pub_", "LLibOrgBouncycastleOpenpgpPGPPublicKey;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "priv_", "LLibOrgBouncycastleOpenpgpPGPPrivateKey;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleOpenpgpPGPPublicKey;LLibOrgBouncycastleOpenpgpPGPPrivateKey;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpPGPKeyPair = { "PGPKeyPair", "lib.org.bouncycastle.openpgp", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpPGPKeyPair;
}

@end

void LibOrgBouncycastleOpenpgpPGPKeyPair_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpPGPPrivateKey_(LibOrgBouncycastleOpenpgpPGPKeyPair *self, LibOrgBouncycastleOpenpgpPGPPublicKey *pub, LibOrgBouncycastleOpenpgpPGPPrivateKey *priv) {
  NSObject_init(self);
  self->pub_ = pub;
  self->priv_ = priv;
}

LibOrgBouncycastleOpenpgpPGPKeyPair *new_LibOrgBouncycastleOpenpgpPGPKeyPair_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpPGPPrivateKey_(LibOrgBouncycastleOpenpgpPGPPublicKey *pub, LibOrgBouncycastleOpenpgpPGPPrivateKey *priv) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPKeyPair, initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpPGPPrivateKey_, pub, priv)
}

LibOrgBouncycastleOpenpgpPGPKeyPair *create_LibOrgBouncycastleOpenpgpPGPKeyPair_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpPGPPrivateKey_(LibOrgBouncycastleOpenpgpPGPPublicKey *pub, LibOrgBouncycastleOpenpgpPGPPrivateKey *priv) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPKeyPair, initWithLibOrgBouncycastleOpenpgpPGPPublicKey_withLibOrgBouncycastleOpenpgpPGPPrivateKey_, pub, priv)
}

void LibOrgBouncycastleOpenpgpPGPKeyPair_init(LibOrgBouncycastleOpenpgpPGPKeyPair *self) {
  NSObject_init(self);
}

LibOrgBouncycastleOpenpgpPGPKeyPair *new_LibOrgBouncycastleOpenpgpPGPKeyPair_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPKeyPair, init)
}

LibOrgBouncycastleOpenpgpPGPKeyPair *create_LibOrgBouncycastleOpenpgpPGPKeyPair_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPKeyPair, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpPGPKeyPair)
