//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/asn1/McEliecePublicKey.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "GF2Matrix.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "McEliecePublicKey.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastlePqcAsn1McEliecePublicKey () {
 @public
  jint n_;
  jint t_;
  LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *g_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcAsn1McEliecePublicKey, g_, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)

__attribute__((unused)) static void LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastlePqcAsn1McEliecePublicKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastlePqcAsn1McEliecePublicKey *new_LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastlePqcAsn1McEliecePublicKey *create_LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastlePqcAsn1McEliecePublicKey

- (instancetype)initWithInt:(jint)n
                    withInt:(jint)t
withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix:(LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)g {
  LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(self, n, t, g);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (jint)getN {
  return n_;
}

- (jint)getT {
  return t_;
}

- (LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *)getG {
  return new_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(g_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(n_)];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(t_)];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_([((LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *) nil_chk(g_)) getEncoded])];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (LibOrgBouncycastlePqcAsn1McEliecePublicKey *)getInstanceWithId:(id)o {
  return LibOrgBouncycastlePqcAsn1McEliecePublicKey_getInstanceWithId_(o);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcAsn1McEliecePublicKey;", 0x9, 2, 3, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithInt:withInt:withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[2].selector = @selector(getN);
  methods[3].selector = @selector(getT);
  methods[4].selector = @selector(getG);
  methods[5].selector = @selector(toASN1Primitive);
  methods[6].selector = @selector(getInstanceWithId:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "n_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "t_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "g_", "LLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "IILLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcAsn1McEliecePublicKey = { "McEliecePublicKey", "lib.org.bouncycastle.pqc.asn1", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcAsn1McEliecePublicKey;
}

@end

void LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(LibOrgBouncycastlePqcAsn1McEliecePublicKey *self, jint n, jint t, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *g) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->n_ = n;
  self->t_ = t;
  self->g_ = new_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(g);
}

LibOrgBouncycastlePqcAsn1McEliecePublicKey *new_LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(jint n, jint t, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *g) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcAsn1McEliecePublicKey, initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_, n, t, g)
}

LibOrgBouncycastlePqcAsn1McEliecePublicKey *create_LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_(jint n, jint t, LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix *g) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcAsn1McEliecePublicKey, initWithInt_withInt_withLibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_, n, t, g)
}

void LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastlePqcAsn1McEliecePublicKey *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  JavaMathBigInteger *bigN = [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(((LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0], [LibOrgBouncycastleAsn1ASN1Integer class])))) getValue];
  self->n_ = [((JavaMathBigInteger *) nil_chk(bigN)) intValue];
  JavaMathBigInteger *bigT = [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(((LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([seq getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1Integer class])))) getValue];
  self->t_ = [((JavaMathBigInteger *) nil_chk(bigT)) intValue];
  self->g_ = new_LibOrgBouncycastlePqcMathLinearalgebraGF2Matrix_initWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(((LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk([seq getObjectAtWithInt:2], [LibOrgBouncycastleAsn1ASN1OctetString class])))) getOctets]);
}

LibOrgBouncycastlePqcAsn1McEliecePublicKey *new_LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcAsn1McEliecePublicKey, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastlePqcAsn1McEliecePublicKey *create_LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcAsn1McEliecePublicKey, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastlePqcAsn1McEliecePublicKey *LibOrgBouncycastlePqcAsn1McEliecePublicKey_getInstanceWithId_(id o) {
  LibOrgBouncycastlePqcAsn1McEliecePublicKey_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastlePqcAsn1McEliecePublicKey class]]) {
    return (LibOrgBouncycastlePqcAsn1McEliecePublicKey *) o;
  }
  else if (o != nil) {
    return new_LibOrgBouncycastlePqcAsn1McEliecePublicKey_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcAsn1McEliecePublicKey)