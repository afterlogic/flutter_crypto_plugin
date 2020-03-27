//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/collection/KeyRingCollection.java
//

#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "KeyRingCollection.h"
#include "KeyRingReader.h"
#include "PGPPublicKey.h"
#include "PGPPublicKeyRing.h"
#include "PGPPublicKeyRingCollection.h"
#include "PGPSecretKeyRing.h"
#include "PGPSecretKeyRingCollection.h"
#include "java/io/File.h"
#include "java/io/FileInputStream.h"
#include "java/io/InputStream.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Long.h"
#include "java/lang/NullPointerException.h"
#include "java/util/logging/Level.h"
#include "java/util/logging/Logger.h"

@interface LibComAfterlogicPgpKeyCollectionKeyRingCollection () {
 @public
  LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *publicKeys_;
  LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *secretKeys_;
}

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyCollectionKeyRingCollection, publicKeys_, LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)
J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyCollectionKeyRingCollection, secretKeys_, LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)

inline JavaUtilLoggingLogger *LibComAfterlogicPgpKeyCollectionKeyRingCollection_get_LOGGER(void);
static JavaUtilLoggingLogger *LibComAfterlogicPgpKeyCollectionKeyRingCollection_LOGGER;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibComAfterlogicPgpKeyCollectionKeyRingCollection, LOGGER, JavaUtilLoggingLogger *)

J2OBJC_INITIALIZED_DEFN(LibComAfterlogicPgpKeyCollectionKeyRingCollection)

@implementation LibComAfterlogicPgpKeyCollectionKeyRingCollection

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)publicKeyRings
                    withLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)secretKeyRings {
  LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_withLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_(self, publicKeyRings, secretKeyRings);
  return self;
}

- (instancetype)initWithJavaIoFile:(JavaIoFile *)pubRingFile
                    withJavaIoFile:(JavaIoFile *)secRingFile {
  LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithJavaIoFile_withJavaIoFile_(self, pubRingFile, secRingFile);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)publicKeyRings {
  LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_(self, publicKeyRings);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)secretKeyRings {
  LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_(self, secretKeyRings);
  return self;
}

- (void)importPublicKeysWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *)publicKeyRings {
  if (self->publicKeys_ == nil) {
    self->publicKeys_ = publicKeyRings;
    return;
  }
  for (LibOrgBouncycastleOpenpgpPGPPublicKeyRing * __strong keyRing in nil_chk(publicKeyRings)) {
    @try {
      self->publicKeys_ = LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_addPublicKeyRingWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_withLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(self->publicKeys_, keyRing);
    }
    @catch (JavaLangIllegalArgumentException *e) {
      [((JavaUtilLoggingLogger *) nil_chk(LibComAfterlogicPgpKeyCollectionKeyRingCollection_LOGGER)) logWithJavaUtilLoggingLevel:JreLoadStatic(JavaUtilLoggingLevel, FINE) withNSString:JreStrcat("$$$", @"Keyring ", JavaLangLong_toHexStringWithLong_([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk([((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk(keyRing)) getPublicKey])) getKeyID]), @" is already included in the collection. Skip!")];
    }
  }
}

- (void)importSecretKeysWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *)secretKeyRings {
  if (self->secretKeys_ == nil) {
    self->secretKeys_ = secretKeyRings;
    return;
  }
  for (LibOrgBouncycastleOpenpgpPGPSecretKeyRing * __strong keyRing in nil_chk(secretKeyRings)) {
    @try {
      self->secretKeys_ = LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_addSecretKeyRingWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_withLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(self->secretKeys_, keyRing);
    }
    @catch (JavaLangIllegalArgumentException *e) {
      [((JavaUtilLoggingLogger *) nil_chk(LibComAfterlogicPgpKeyCollectionKeyRingCollection_LOGGER)) logWithJavaUtilLoggingLevel:JreLoadStatic(JavaUtilLoggingLevel, FINE) withNSString:JreStrcat("$$$", @"Keyring ", JavaLangLong_toHexStringWithLong_([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk([((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk(keyRing)) getPublicKey])) getKeyID]), @" is already included in the collection. Skip!")];
    }
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, 2, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 5, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 6, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:withLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:);
  methods[1].selector = @selector(initWithJavaIoFile:withJavaIoFile:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:);
  methods[4].selector = @selector(importPublicKeysWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection:);
  methods[5].selector = @selector(importSecretKeysWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "LOGGER", "LJavaUtilLoggingLogger;", .constantValue.asLong = 0, 0x1a, -1, 7, -1, -1 },
    { "publicKeys_", "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "secretKeys_", "LLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;LLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;", "LJavaIoFile;LJavaIoFile;", "LJavaIoIOException;LLibOrgBouncycastleOpenpgpPGPException;", "LLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection;", "LLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection;", "importPublicKeys", "importSecretKeys", &LibComAfterlogicPgpKeyCollectionKeyRingCollection_LOGGER };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyCollectionKeyRingCollection = { "KeyRingCollection", "lib.com.afterlogic.pgp.key.collection", ptrTable, methods, fields, 7, 0x1, 6, 3, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyCollectionKeyRingCollection;
}

+ (void)initialize {
  if (self == [LibComAfterlogicPgpKeyCollectionKeyRingCollection class]) {
    LibComAfterlogicPgpKeyCollectionKeyRingCollection_LOGGER = JavaUtilLoggingLogger_getLoggerWithNSString_([LibComAfterlogicPgpKeyCollectionKeyRingCollection_class_() getName]);
    J2OBJC_SET_INITIALIZED(LibComAfterlogicPgpKeyCollectionKeyRingCollection)
  }
}

@end

void LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_withLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_(LibComAfterlogicPgpKeyCollectionKeyRingCollection *self, LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *publicKeyRings, LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *secretKeyRings) {
  NSObject_init(self);
  self->publicKeys_ = publicKeyRings;
  self->secretKeys_ = secretKeyRings;
}

LibComAfterlogicPgpKeyCollectionKeyRingCollection *new_LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_withLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *publicKeyRings, LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *secretKeyRings) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyCollectionKeyRingCollection, initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_withLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_, publicKeyRings, secretKeyRings)
}

LibComAfterlogicPgpKeyCollectionKeyRingCollection *create_LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_withLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *publicKeyRings, LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *secretKeyRings) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyCollectionKeyRingCollection, initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_withLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_, publicKeyRings, secretKeyRings)
}

void LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithJavaIoFile_withJavaIoFile_(LibComAfterlogicPgpKeyCollectionKeyRingCollection *self, JavaIoFile *pubRingFile, JavaIoFile *secRingFile) {
  NSObject_init(self);
  if (pubRingFile == nil && secRingFile == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"pubRingFile and secRingFile cannot BOTH be null.");
  }
  if (pubRingFile != nil) {
    JavaIoInputStream *pubRingIn = new_JavaIoFileInputStream_initWithJavaIoFile_(pubRingFile);
    self->publicKeys_ = [new_LibComAfterlogicPgpKeyParsingKeyRingReader_init() publicKeyRingCollectionWithJavaIoInputStream:pubRingIn];
    [pubRingIn close];
  }
  if (secRingFile != nil) {
    JavaIoInputStream *secRingIn = new_JavaIoFileInputStream_initWithJavaIoFile_(secRingFile);
    self->secretKeys_ = [new_LibComAfterlogicPgpKeyParsingKeyRingReader_init() secretKeyRingCollectionWithJavaIoInputStream:secRingIn];
    [secRingIn close];
  }
}

LibComAfterlogicPgpKeyCollectionKeyRingCollection *new_LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithJavaIoFile_withJavaIoFile_(JavaIoFile *pubRingFile, JavaIoFile *secRingFile) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyCollectionKeyRingCollection, initWithJavaIoFile_withJavaIoFile_, pubRingFile, secRingFile)
}

LibComAfterlogicPgpKeyCollectionKeyRingCollection *create_LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithJavaIoFile_withJavaIoFile_(JavaIoFile *pubRingFile, JavaIoFile *secRingFile) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyCollectionKeyRingCollection, initWithJavaIoFile_withJavaIoFile_, pubRingFile, secRingFile)
}

void LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_(LibComAfterlogicPgpKeyCollectionKeyRingCollection *self, LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *publicKeyRings) {
  NSObject_init(self);
  self->publicKeys_ = publicKeyRings;
}

LibComAfterlogicPgpKeyCollectionKeyRingCollection *new_LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *publicKeyRings) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyCollectionKeyRingCollection, initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_, publicKeyRings)
}

LibComAfterlogicPgpKeyCollectionKeyRingCollection *create_LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_(LibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection *publicKeyRings) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyCollectionKeyRingCollection, initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRingCollection_, publicKeyRings)
}

void LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_(LibComAfterlogicPgpKeyCollectionKeyRingCollection *self, LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *secretKeyRings) {
  NSObject_init(self);
  self->secretKeys_ = secretKeyRings;
}

LibComAfterlogicPgpKeyCollectionKeyRingCollection *new_LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *secretKeyRings) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyCollectionKeyRingCollection, initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_, secretKeyRings)
}

LibComAfterlogicPgpKeyCollectionKeyRingCollection *create_LibComAfterlogicPgpKeyCollectionKeyRingCollection_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_(LibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection *secretKeyRings) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyCollectionKeyRingCollection, initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRingCollection_, secretKeyRings)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyCollectionKeyRingCollection)
