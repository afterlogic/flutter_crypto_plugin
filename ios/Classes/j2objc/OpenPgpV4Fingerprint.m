//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/OpenPgpV4Fingerprint.java
//

#include "Hex.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "OpenPgpV4Fingerprint.h"
#include "PGPPublicKey.h"
#include "PGPPublicKeyRing.h"
#include "PGPSecretKey.h"
#include "PGPSecretKeyRing.h"
#include "java/lang/CharSequence.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/nio/Buffer.h"
#include "java/nio/ByteBuffer.h"
#include "java/nio/charset/Charset.h"
#include "java/util/stream/IntStream.h"

@interface LibComAfterlogicPgpKeyOpenPgpV4Fingerprint () {
 @public
  NSString *fingerprint_;
}

+ (jboolean)isValidWithNSString:(NSString *)fp;

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, fingerprint_, NSString *)

__attribute__((unused)) static jboolean LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_isValidWithNSString_(NSString *fp);

@implementation LibComAfterlogicPgpKeyOpenPgpV4Fingerprint

- (instancetype)initWithNSString:(NSString *)fingerprint {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithNSString_(self, fingerprint);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)bytes {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithByteArray_(self, bytes);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPPublicKey:(LibOrgBouncycastleOpenpgpPGPPublicKey *)key {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, key);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPSecretKey:(LibOrgBouncycastleOpenpgpPGPSecretKey *)key {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPSecretKey_(self, key);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *)ring {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(self, ring);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *)ring {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(self, ring);
  return self;
}

+ (jboolean)isValidWithNSString:(NSString *)fp {
  return LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_isValidWithNSString_(fp);
}

- (jlong)getKeyId {
  IOSByteArray *bytes = LibOrgBouncycastleUtilEncodersHex_decodeWithByteArray_([((NSString *) nil_chk([self description])) java_getBytesWithCharset:JavaNioCharsetCharset_forNameWithNSString_(@"UTF-8")]);
  JavaNioByteBuffer *buf = JavaNioByteBuffer_wrapWithByteArray_(bytes);
  (void) [((JavaNioByteBuffer *) nil_chk(buf)) positionWithInt:12];
  return [buf getLong];
}

- (jboolean)isEqual:(id)other {
  if (other == nil) {
    return false;
  }
  if (!([JavaLangCharSequence_class_() isInstance:other])) {
    return false;
  }
  return [((NSString *) nil_chk([self description])) isEqual:[other description]];
}

- (NSUInteger)hash {
  return ((jint) [((NSString *) nil_chk(fingerprint_)) hash]);
}

- (jint)java_length {
  return [((NSString *) nil_chk(fingerprint_)) java_length];
}

- (jchar)charAtWithInt:(jint)i {
  return [((NSString *) nil_chk(fingerprint_)) charAtWithInt:i];
}

- (id<JavaLangCharSequence>)subSequenceFrom:(jint)i
                                         to:(jint)i1 {
  return [((NSString *) nil_chk(fingerprint_)) subSequenceFrom:i to:i1];
}

- (NSString *)description {
  return fingerprint_;
}

- (jint)compareToWithId:(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *)openPgpV4Fingerprint {
  (void) cast_chk(openPgpV4Fingerprint, [LibComAfterlogicPgpKeyOpenPgpV4Fingerprint class]);
  return [((NSString *) nil_chk(fingerprint_)) compareToWithId:((LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *) nil_chk(openPgpV4Fingerprint))->fingerprint_];
}

- (id<JavaUtilStreamIntStream>)chars {
  return JavaLangCharSequence_chars(self);
}

- (id<JavaUtilStreamIntStream>)codePoints {
  return JavaLangCharSequence_codePoints(self);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, "Z", 0xa, 6, 0, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 7, 8, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 9, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 10, -1, -1, -1, -1, -1 },
    { NULL, "C", 0x1, 11, 12, -1, -1, -1, -1 },
    { NULL, "LJavaLangCharSequence;", 0x1, 13, 14, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 15, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 16, 17, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:);
  methods[1].selector = @selector(initWithByteArray:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPPublicKey:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPSecretKey:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing:);
  methods[5].selector = @selector(initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing:);
  methods[6].selector = @selector(isValidWithNSString:);
  methods[7].selector = @selector(getKeyId);
  methods[8].selector = @selector(isEqual:);
  methods[9].selector = @selector(hash);
  methods[10].selector = @selector(java_length);
  methods[11].selector = @selector(charAtWithInt:);
  methods[12].selector = @selector(subSequenceFrom:to:);
  methods[13].selector = @selector(description);
  methods[14].selector = @selector(compareToWithId:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "fingerprint_", "LNSString;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;", "[B", "LLibOrgBouncycastleOpenpgpPGPPublicKey;", "LLibOrgBouncycastleOpenpgpPGPSecretKey;", "LLibOrgBouncycastleOpenpgpPGPPublicKeyRing;", "LLibOrgBouncycastleOpenpgpPGPSecretKeyRing;", "isValid", "equals", "LNSObject;", "hashCode", "length", "charAt", "I", "subSequence", "II", "toString", "compareTo", "LLibComAfterlogicPgpKeyOpenPgpV4Fingerprint;", "Ljava/lang/Object;Ljava/lang/CharSequence;Ljava/lang/Comparable<Llib/com/afterlogic/pgp/key/OpenPgpV4Fingerprint;>;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyOpenPgpV4Fingerprint = { "OpenPgpV4Fingerprint", "lib.com.afterlogic.pgp.key", ptrTable, methods, fields, 7, 0x1, 15, 1, -1, -1, -1, 18, -1 };
  return &_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint;
}

@end

void LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithNSString_(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *self, NSString *fingerprint) {
  NSObject_init(self);
  NSString *fp = [((NSString *) nil_chk([((NSString *) nil_chk(fingerprint)) java_trim])) uppercaseString];
  if (!LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_isValidWithNSString_(fp)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$$", @"Fingerprint ", fingerprint, @" does not appear to be a valid OpenPGP v4 fingerprint."));
  }
  self->fingerprint_ = fp;
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *new_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithNSString_(NSString *fingerprint) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithNSString_, fingerprint)
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *create_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithNSString_(NSString *fingerprint) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithNSString_, fingerprint)
}

void LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithByteArray_(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *self, IOSByteArray *bytes) {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithNSString_(self, [NSString java_stringWithBytes:bytes charset:JavaNioCharsetCharset_forNameWithNSString_(@"UTF-8")]);
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *new_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithByteArray_(IOSByteArray *bytes) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithByteArray_, bytes)
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *create_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithByteArray_(IOSByteArray *bytes) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithByteArray_, bytes)
}

void LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *self, LibOrgBouncycastleOpenpgpPGPPublicKey *key) {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithByteArray_(self, LibOrgBouncycastleUtilEncodersHex_encodeWithByteArray_([((LibOrgBouncycastleOpenpgpPGPPublicKey *) nil_chk(key)) getFingerprint]));
  if ([key getVersion] != 4) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Key is not a v4 OpenPgp key.");
  }
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *new_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPPublicKey *key) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithLibOrgBouncycastleOpenpgpPGPPublicKey_, key)
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *create_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_(LibOrgBouncycastleOpenpgpPGPPublicKey *key) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithLibOrgBouncycastleOpenpgpPGPPublicKey_, key)
}

void LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPSecretKey_(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *self, LibOrgBouncycastleOpenpgpPGPSecretKey *key) {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, [((LibOrgBouncycastleOpenpgpPGPSecretKey *) nil_chk(key)) getPublicKey]);
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *new_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPSecretKey_(LibOrgBouncycastleOpenpgpPGPSecretKey *key) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithLibOrgBouncycastleOpenpgpPGPSecretKey_, key)
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *create_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPSecretKey_(LibOrgBouncycastleOpenpgpPGPSecretKey *key) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithLibOrgBouncycastleOpenpgpPGPSecretKey_, key)
}

void LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *self, LibOrgBouncycastleOpenpgpPGPPublicKeyRing *ring) {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, [((LibOrgBouncycastleOpenpgpPGPPublicKeyRing *) nil_chk(ring)) getPublicKey]);
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *new_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *ring) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_, ring)
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *create_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_(LibOrgBouncycastleOpenpgpPGPPublicKeyRing *ring) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithLibOrgBouncycastleOpenpgpPGPPublicKeyRing_, ring)
}

void LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *self, LibOrgBouncycastleOpenpgpPGPSecretKeyRing *ring) {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPPublicKey_(self, [((LibOrgBouncycastleOpenpgpPGPSecretKeyRing *) nil_chk(ring)) getPublicKey]);
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *new_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *ring) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_, ring)
}

LibComAfterlogicPgpKeyOpenPgpV4Fingerprint *create_LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_(LibOrgBouncycastleOpenpgpPGPSecretKeyRing *ring) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint, initWithLibOrgBouncycastleOpenpgpPGPSecretKeyRing_, ring)
}

jboolean LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_isValidWithNSString_(NSString *fp) {
  LibComAfterlogicPgpKeyOpenPgpV4Fingerprint_initialize();
  return [((NSString *) nil_chk(fp)) java_matches:@"[0-9A-F]{40}"];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyOpenPgpV4Fingerprint)