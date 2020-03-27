//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/asn1/XMSSPublicKey.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "Arrays.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "XMSSPublicKey.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastlePqcAsn1XMSSPublicKey () {
 @public
  IOSByteArray *publicSeed_;
  IOSByteArray *root_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcAsn1XMSSPublicKey, publicSeed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcAsn1XMSSPublicKey, root_, IOSByteArray *)

__attribute__((unused)) static void LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastlePqcAsn1XMSSPublicKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastlePqcAsn1XMSSPublicKey *new_LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastlePqcAsn1XMSSPublicKey *create_LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastlePqcAsn1XMSSPublicKey

- (instancetype)initWithByteArray:(IOSByteArray *)publicSeed
                    withByteArray:(IOSByteArray *)root {
  LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithByteArray_withByteArray_(self, publicSeed, root);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastlePqcAsn1XMSSPublicKey *)getInstanceWithId:(id)o {
  return LibOrgBouncycastlePqcAsn1XMSSPublicKey_getInstanceWithId_(o);
}

- (IOSByteArray *)getPublicSeed {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(publicSeed_);
}

- (IOSByteArray *)getRoot {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(root_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(0)];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(publicSeed_)];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(root_)];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcAsn1XMSSPublicKey;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:withByteArray:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getPublicSeed);
  methods[4].selector = @selector(getRoot);
  methods[5].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "publicSeed_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "root_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B[B", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcAsn1XMSSPublicKey = { "XMSSPublicKey", "lib.org.bouncycastle.pqc.asn1", ptrTable, methods, fields, 7, 0x1, 6, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcAsn1XMSSPublicKey;
}

@end

void LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithByteArray_withByteArray_(LibOrgBouncycastlePqcAsn1XMSSPublicKey *self, IOSByteArray *publicSeed, IOSByteArray *root) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->publicSeed_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(publicSeed);
  self->root_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(root);
}

LibOrgBouncycastlePqcAsn1XMSSPublicKey *new_LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithByteArray_withByteArray_(IOSByteArray *publicSeed, IOSByteArray *root) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcAsn1XMSSPublicKey, initWithByteArray_withByteArray_, publicSeed, root)
}

LibOrgBouncycastlePqcAsn1XMSSPublicKey *create_LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithByteArray_withByteArray_(IOSByteArray *publicSeed, IOSByteArray *root) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcAsn1XMSSPublicKey, initWithByteArray_withByteArray_, publicSeed, root)
}

void LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastlePqcAsn1XMSSPublicKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (![((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]))) getValue])) isEqual:JavaMathBigInteger_valueOfWithLong_(0)]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"unknown version of sequence");
  }
  self->publicSeed_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:1]))) getOctets]);
  self->root_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:2]))) getOctets]);
}

LibOrgBouncycastlePqcAsn1XMSSPublicKey *new_LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcAsn1XMSSPublicKey, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastlePqcAsn1XMSSPublicKey *create_LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcAsn1XMSSPublicKey, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastlePqcAsn1XMSSPublicKey *LibOrgBouncycastlePqcAsn1XMSSPublicKey_getInstanceWithId_(id o) {
  LibOrgBouncycastlePqcAsn1XMSSPublicKey_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastlePqcAsn1XMSSPublicKey class]]) {
    return (LibOrgBouncycastlePqcAsn1XMSSPublicKey *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastlePqcAsn1XMSSPublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcAsn1XMSSPublicKey)
