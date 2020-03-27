//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/selection/keyring/impl/Whitelist.java
//

#include "J2ObjC_source.h"
#include "MultiMap.h"
#include "PGPPublicKey.h"
#include "PGPPublicKeyRing.h"
#include "PGPSecretKeyRing.h"
#include "PublicKeyRingSelectionStrategy.h"
#include "SecretKeyRingSelectionStrategy.h"
#include "Whitelist.h"
#include "java/lang/Long.h"
#include "java/util/Map.h"
#include "java/util/Set.h"

@interface LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy () {
 @public
  LibComAfterlogicPgpUtilMultiMap *whitelist_;
}

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy, whitelist_, LibComAfterlogicPgpUtilMultiMap *)

@interface LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy () {
 @public
  LibComAfterlogicPgpUtilMultiMap *whitelist_;
}

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy, whitelist_, LibComAfterlogicPgpUtilMultiMap *)

@implementation LibComAfterlogicPgpKeySelectionKeyringImplWhitelist

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_init(self);
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
  static const void *ptrTable[] = { "LLibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy;LLibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyringImplWhitelist = { "Whitelist", "lib.com.afterlogic.pgp.key.selection.keyring.impl", ptrTable, methods, NULL, 7, 0x1, 1, 0, -1, 0, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist;
}

@end

void LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_init(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist *self) {
  NSObject_init(self);
}

LibComAfterlogicPgpKeySelectionKeyringImplWhitelist *new_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_init() {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist, init)
}

LibComAfterlogicPgpKeySelectionKeyringImplWhitelist *create_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_init() {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist)

@implementation LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy

- (instancetype)initWithLibComAfterlogicPgpUtilMultiMap:(LibComAfterlogicPgpUtilMultiMap *)whitelist {
  LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy_initWithLibComAfterlogicPgpUtilMultiMap_(self, whitelist);
  return self;
}

- (instancetype)initWithJavaUtilMap:(id<JavaUtilMap>)whitelist {
  LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy_initWithJavaUtilMap_(self, whitelist);
  return self;
}

- (jboolean)acceptWithId:(id)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)keyRing {
  id<JavaUtilSet> whitelistedKeyIds = [((LibComAfterlogicPgpUtilMultiMap *) nil_chk(whitelist_)) getWithId:identifier];
  if (whitelistedKeyIds == nil) {
    return false;
  }
  return [whitelistedKeyIds containsWithId:JavaLangLong_valueOfWithLong_([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk([((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk(keyRing)) getPublicKey])) getKeyID])];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, 1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, 3, -1, -1 },
    { NULL, "Z", 0x1, 4, 5, -1, 6, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpUtilMultiMap:);
  methods[1].selector = @selector(initWithJavaUtilMap:);
  methods[2].selector = @selector(acceptWithId:withId:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "whitelist_", "LLibComAfterlogicPgpUtilMultiMap;", .constantValue.asLong = 0, 0x12, -1, -1, 7, -1 },
  };
  static const void *ptrTable[] = { "LLibComAfterlogicPgpUtilMultiMap;", "(Llib/com/afterlogic/pgp/util/MultiMap<TO;Ljava/lang/Long;>;)V", "LJavaUtilMap;", "(Ljava/util/Map<TO;Ljava/util/Set<Ljava/lang/Long;>;>;)V", "accept", "LNSObject;LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", "(TO;Llib/org/bouncycastle/openpgp/PGPPublicKeyRing;)Z", "Llib/com/afterlogic/pgp/util/MultiMap<TO;Ljava/lang/Long;>;", "LLibComAfterlogicPgpKeySelectionKeyringImplWhitelist;", "<O:Ljava/lang/Object;>Llib/com/afterlogic/pgp/key/selection/keyring/PublicKeyRingSelectionStrategy<TO;>;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy = { "PubRingSelectionStrategy", "lib.com.afterlogic.pgp.key.selection.keyring.impl", ptrTable, methods, fields, 7, 0x9, 3, 1, 8, -1, -1, 9, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy;
}

@end

void LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy_initWithLibComAfterlogicPgpUtilMultiMap_(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy *self, LibComAfterlogicPgpUtilMultiMap *whitelist) {
  LibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy_init(self);
  self->whitelist_ = whitelist;
}

LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy_initWithLibComAfterlogicPgpUtilMultiMap_(LibComAfterlogicPgpUtilMultiMap *whitelist) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy, initWithLibComAfterlogicPgpUtilMultiMap_, whitelist)
}

LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy_initWithLibComAfterlogicPgpUtilMultiMap_(LibComAfterlogicPgpUtilMultiMap *whitelist) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy, initWithLibComAfterlogicPgpUtilMultiMap_, whitelist)
}

void LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy_initWithJavaUtilMap_(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy *self, id<JavaUtilMap> whitelist) {
  LibComAfterlogicPgpKeySelectionKeyringPublicKeyRingSelectionStrategy_init(self);
  self->whitelist_ = new_LibComAfterlogicPgpUtilMultiMap_initWithJavaUtilMap_(whitelist);
}

LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy_initWithJavaUtilMap_(id<JavaUtilMap> whitelist) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy, initWithJavaUtilMap_, whitelist)
}

LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy_initWithJavaUtilMap_(id<JavaUtilMap> whitelist) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy, initWithJavaUtilMap_, whitelist)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_PubRingSelectionStrategy)

@implementation LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy

- (instancetype)initWithLibComAfterlogicPgpUtilMultiMap:(LibComAfterlogicPgpUtilMultiMap *)whitelist {
  LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy_initWithLibComAfterlogicPgpUtilMultiMap_(self, whitelist);
  return self;
}

- (instancetype)initWithJavaUtilMap:(id<JavaUtilMap>)whitelist {
  LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy_initWithJavaUtilMap_(self, whitelist);
  return self;
}

- (jboolean)acceptWithId:(id)identifier
                  withId:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)keyRing {
  id<JavaUtilSet> whitelistedKeyIds = [((LibComAfterlogicPgpUtilMultiMap *) nil_chk(whitelist_)) getWithId:identifier];
  if (whitelistedKeyIds == nil) {
    return false;
  }
  return [whitelistedKeyIds containsWithId:JavaLangLong_valueOfWithLong_([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk([((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk(keyRing)) getPublicKey])) getKeyID])];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, 1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, 3, -1, -1 },
    { NULL, "Z", 0x1, 4, 5, -1, 6, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpUtilMultiMap:);
  methods[1].selector = @selector(initWithJavaUtilMap:);
  methods[2].selector = @selector(acceptWithId:withId:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "whitelist_", "LLibComAfterlogicPgpUtilMultiMap;", .constantValue.asLong = 0, 0x12, -1, -1, 7, -1 },
  };
  static const void *ptrTable[] = { "LLibComAfterlogicPgpUtilMultiMap;", "(Llib/com/afterlogic/pgp/util/MultiMap<TO;Ljava/lang/Long;>;)V", "LJavaUtilMap;", "(Ljava/util/Map<TO;Ljava/util/Set<Ljava/lang/Long;>;>;)V", "accept", "LNSObject;LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", "(TO;Llib/org/bouncycastle/openpgp/PGPSecretKeyRing;)Z", "Llib/com/afterlogic/pgp/util/MultiMap<TO;Ljava/lang/Long;>;", "LLibComAfterlogicPgpKeySelectionKeyringImplWhitelist;", "<O:Ljava/lang/Object;>Llib/com/afterlogic/pgp/key/selection/keyring/SecretKeyRingSelectionStrategy<TO;>;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy = { "SecRingSelectionStrategy", "lib.com.afterlogic.pgp.key.selection.keyring.impl", ptrTable, methods, fields, 7, 0x9, 3, 1, 8, -1, -1, 9, -1 };
  return &_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy;
}

@end

void LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy_initWithLibComAfterlogicPgpUtilMultiMap_(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy *self, LibComAfterlogicPgpUtilMultiMap *whitelist) {
  LibComAfterlogicPgpKeySelectionKeyringSecretKeyRingSelectionStrategy_init(self);
  self->whitelist_ = whitelist;
}

LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy_initWithLibComAfterlogicPgpUtilMultiMap_(LibComAfterlogicPgpUtilMultiMap *whitelist) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy, initWithLibComAfterlogicPgpUtilMultiMap_, whitelist)
}

LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy_initWithLibComAfterlogicPgpUtilMultiMap_(LibComAfterlogicPgpUtilMultiMap *whitelist) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy, initWithLibComAfterlogicPgpUtilMultiMap_, whitelist)
}

void LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy_initWithJavaUtilMap_(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy *self, id<JavaUtilMap> whitelist) {
  LibComAfterlogicPgpKeySelectionKeyringSecretKeyRingSelectionStrategy_init(self);
  self->whitelist_ = new_LibComAfterlogicPgpUtilMultiMap_initWithJavaUtilMap_(whitelist);
}

LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy *new_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy_initWithJavaUtilMap_(id<JavaUtilMap> whitelist) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy, initWithJavaUtilMap_, whitelist)
}

LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy *create_LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy_initWithJavaUtilMap_(id<JavaUtilMap> whitelist) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy, initWithJavaUtilMap_, whitelist)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeySelectionKeyringImplWhitelist_SecRingSelectionStrategy)
