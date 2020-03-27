//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/asn1/PqcAsn1XMSSMTPrivateKey.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "Arrays.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PqcAsn1XMSSMTPrivateKey.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey () {
 @public
  jint index_;
  IOSByteArray *secretKeySeed_;
  IOSByteArray *secretKeyPRF_;
  IOSByteArray *publicSeed_;
  IOSByteArray *root_;
  IOSByteArray *bdsState_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey, secretKeySeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey, secretKeyPRF_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey, publicSeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey, root_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey, bdsState_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *new_LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *create_LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey

- (instancetype)initWithInt:(jint)index
              withByteArray:(IOSByteArray *)secretKeySeed
              withByteArray:(IOSByteArray *)secretKeyPRF
              withByteArray:(IOSByteArray *)publicSeed
              withByteArray:(IOSByteArray *)root
              withByteArray:(IOSByteArray *)bdsState {
  LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_(self, index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsState);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *)getInstanceWithId:(id)o {
  return LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_getInstanceWithId_(o);
}

- (jint)getIndex {
  return index_;
}

- (IOSByteArray *)getSecretKeySeed {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(secretKeySeed_);
}

- (IOSByteArray *)getSecretKeyPRF {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(secretKeyPRF_);
}

- (IOSByteArray *)getPublicSeed {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(publicSeed_);
}

- (IOSByteArray *)getRoot {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(root_);
}

- (IOSByteArray *)getBdsState {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(bdsState_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(0)];
  LibOrgBouncycastleAsn1ASN1EncodableVector *vK = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [vK addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(index_)];
  [vK addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(secretKeySeed_)];
  [vK addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(secretKeyPRF_)];
  [vK addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(publicSeed_)];
  [vK addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(root_)];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(vK)];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(true, 0, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(bdsState_))];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withByteArray:withByteArray:withByteArray:withByteArray:withByteArray:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getIndex);
  methods[4].selector = @selector(getSecretKeySeed);
  methods[5].selector = @selector(getSecretKeyPRF);
  methods[6].selector = @selector(getPublicSeed);
  methods[7].selector = @selector(getRoot);
  methods[8].selector = @selector(getBdsState);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "index_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "secretKeySeed_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "secretKeyPRF_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "publicSeed_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "root_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "bdsState_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "I[B[B[B[B[B", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey = { "PqcAsn1XMSSMTPrivateKey", "lib.org.bouncycastle.pqc.asn1", ptrTable, methods, fields, 7, 0x1, 10, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey;
}

@end

void LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *self, jint index, IOSByteArray *secretKeySeed, IOSByteArray *secretKeyPRF, IOSByteArray *publicSeed, IOSByteArray *root, IOSByteArray *bdsState) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->index_ = index;
  self->secretKeySeed_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(secretKeySeed);
  self->secretKeyPRF_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(secretKeyPRF);
  self->publicSeed_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(publicSeed);
  self->root_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(root);
  self->bdsState_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(bdsState);
}

LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *new_LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_(jint index, IOSByteArray *secretKeySeed, IOSByteArray *secretKeyPRF, IOSByteArray *publicSeed, IOSByteArray *root, IOSByteArray *bdsState) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey, initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_, index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsState)
}

LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *create_LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_(jint index, IOSByteArray *secretKeySeed, IOSByteArray *secretKeyPRF, IOSByteArray *publicSeed, IOSByteArray *root, IOSByteArray *bdsState) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey, initWithInt_withByteArray_withByteArray_withByteArray_withByteArray_withByteArray_, index, secretKeySeed, secretKeyPRF, publicSeed, root, bdsState)
}

void LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (![((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]))) getValue])) isEqual:JavaMathBigInteger_valueOfWithLong_(0)]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown version of sequence");
  }
  if ([seq size] != 2 && [seq size] != 3) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"key sequence wrong size");
  }
  LibOrgBouncycastleAsn1ASN1Sequence *keySeq = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([seq getObjectAtWithInt:1]);
  self->index_ = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(keySeq)) getObjectAtWithInt:0]))) getValue])) intValue];
  self->secretKeySeed_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([keySeq getObjectAtWithInt:1]))) getOctets]);
  self->secretKeyPRF_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([keySeq getObjectAtWithInt:2]))) getOctets]);
  self->publicSeed_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([keySeq getObjectAtWithInt:3]))) getOctets]);
  self->root_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([keySeq getObjectAtWithInt:4]))) getOctets]);
  if ([seq size] == 3) {
    self->bdsState_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject_getInstanceWithId_([seq getObjectAtWithInt:2]), true))) getOctets]);
  }
  else {
    self->bdsState_ = nil;
  }
}

LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *new_LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *create_LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_getInstanceWithId_(id o) {
  LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey class]]) {
    return (LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcAsn1PqcAsn1XMSSMTPrivateKey)
