//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cryptopro/Gost2814789EncryptedKey.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "Arrays.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "Gost2814789EncryptedKey.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey () {
 @public
  IOSByteArray *encryptedKey_;
  IOSByteArray *maskKey_;
  IOSByteArray *macKey_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey, encryptedKey_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey, maskKey_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey, macKey_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *new_LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *create_LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_getInstanceWithId_(obj);
}

- (instancetype)initWithByteArray:(IOSByteArray *)encryptedKey
                    withByteArray:(IOSByteArray *)macKey {
  LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_(self, encryptedKey, macKey);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)encryptedKey
                    withByteArray:(IOSByteArray *)maskKey
                    withByteArray:(IOSByteArray *)macKey {
  LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_withByteArray_(self, encryptedKey, maskKey, macKey);
  return self;
}

- (IOSByteArray *)getEncryptedKey {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(encryptedKey_);
}

- (IOSByteArray *)getMaskKey {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(maskKey_);
}

- (IOSByteArray *)getMacKey {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(macKey_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(encryptedKey_)];
  if (maskKey_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 0, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(encryptedKey_))];
  }
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(macKey_)];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithByteArray:withByteArray:);
  methods[3].selector = @selector(initWithByteArray:withByteArray:withByteArray:);
  methods[4].selector = @selector(getEncryptedKey);
  methods[5].selector = @selector(getMaskKey);
  methods[6].selector = @selector(getMacKey);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "encryptedKey_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "maskKey_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "macKey_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;", "[B[B", "[B[B[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey = { "Gost2814789EncryptedKey", "lib.org.bouncycastle.asn1.cryptopro", ptrTable, methods, fields, 7, 0x1, 8, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey;
}

@end

void LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] == 2) {
    self->encryptedKey_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:0]))) getOctets]);
    self->macKey_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:1]))) getOctets]);
    self->maskKey_ = nil;
  }
  else if ([seq size] == 3) {
    self->encryptedKey_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:0]))) getOctets]);
    self->maskKey_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithId_([seq getObjectAtWithInt:1]), false))) getOctets]);
    self->macKey_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:2]))) getOctets]);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"unknown sequence length: ", [seq size]));
  }
}

LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *new_LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *create_LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey class]]) {
    return (LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *self, IOSByteArray *encryptedKey, IOSByteArray *macKey) {
  LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_withByteArray_(self, encryptedKey, nil, macKey);
}

LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *new_LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_(IOSByteArray *encryptedKey, IOSByteArray *macKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey, initWithByteArray_withByteArray_, encryptedKey, macKey)
}

LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *create_LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_(IOSByteArray *encryptedKey, IOSByteArray *macKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey, initWithByteArray_withByteArray_, encryptedKey, macKey)
}

void LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_withByteArray_(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *self, IOSByteArray *encryptedKey, IOSByteArray *maskKey, IOSByteArray *macKey) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->encryptedKey_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(encryptedKey);
  self->maskKey_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(maskKey);
  self->macKey_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(macKey);
}

LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *new_LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_withByteArray_(IOSByteArray *encryptedKey, IOSByteArray *maskKey, IOSByteArray *macKey) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey, initWithByteArray_withByteArray_withByteArray_, encryptedKey, maskKey, macKey)
}

LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey *create_LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey_initWithByteArray_withByteArray_withByteArray_(IOSByteArray *encryptedKey, IOSByteArray *maskKey, IOSByteArray *macKey) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey, initWithByteArray_withByteArray_withByteArray_, encryptedKey, maskKey, macKey)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CryptoproGost2814789EncryptedKey)