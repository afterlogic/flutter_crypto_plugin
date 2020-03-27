//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/selection/keyring/impl/ExactUserId.java
//

#include "ExactUserId.h"
#include "J2ObjC_source.h"
#include "PGPPublicKey.h"
#include "PGPPublicKeyRing.h"
#include "PGPSecretKeyRing.h"
#include "PublicKeyRingSelectionStrategy.h"
#include "SecretKeyRingSelectionStrategy.h"
#include "java/util/Iterator.h"

@implementation LibComAfterlogicPgpKeySelectionKeyringImplExactUserId

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "LLibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy;LLibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyringImplExactUserId = { "ExactUserId", "lib.com.afterlogic.pgp.key.selection.keyring.impl", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId;
}

@end

void LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_init(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId *self) {
  NSObject_init(self);
}

LibComAfterlogicPgpKeySelectionKeyringImplExactUserId *new_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId, init)
}

LibComAfterlogicPgpKeySelectionKeyringImplExactUserId *create_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId)

@implementation LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)acceptWithId:(NSString *)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)keyRing {
  id<JavaUtilIterator> userIds = [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk([((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk(keyRing)) getPublicKey])) getUserIDs];
  while ([((id<JavaUtilIterator>) nil_chk(userIds)) hasNext]) {
    if ([((NSString *) nil_chk([userIds next])) isEqual:identifier]) return true;
  }
  return false;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(acceptWithId:withId:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "accept", "LNSString;LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", "LLibComAfterlogicPgpKeySelectionKeyringImplExactUserId;", "Llib/com/afterlogic/pgp/key/selection/keyring/PublicKeyRingSelectionStrategy<Ljava/lang/String;>;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy = { "PubRingSelectionStrategy", "lib.com.afterlogic.pgp.key.selection.keyring.impl", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, 3, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy;
}

@end

void LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy *self) {
  LibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy_init(self);
}

LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy, init)
}

LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_PubRingSelectionStrategy)

@implementation LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)acceptWithId:(NSString *)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)keyRing {
  id<JavaUtilIterator> userIds = [((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk([((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk(keyRing)) getPublicKey])) getUserIDs];
  while ([((id<JavaUtilIterator>) nil_chk(userIds)) hasNext]) {
    if ([((NSString *) nil_chk([userIds next])) isEqual:identifier]) return true;
  }
  return false;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(acceptWithId:withId:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "accept", "LNSString;LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", "LLibComAfterlogicPgpKeySelectionKeyringImplExactUserId;", "Llib/com/afterlogic/pgp/key/selection/keyring/SecretKeyRingSelectionStrategy<Ljava/lang/String;>;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy = { "SecRingSelectionStrategy", "lib.com.afterlogic.pgp.key.selection.keyring.impl", ptrTable, methods, NULL, 7, 0x9, 2, 0, 2, -1, -1, 3, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy;
}

@end

void LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy_init(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy *self) {
  LibComAfterlogicPgpKeySelectionKeyringSecretKeyRingSelectionStrategy_init(self);
}

LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy, init)
}

LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyringImplExactUserId_SecRingSelectionStrategy)
