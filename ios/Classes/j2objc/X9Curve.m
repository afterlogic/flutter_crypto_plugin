//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x9/X9Curve.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "Arrays.h"
#include "DERBitString.h"
#include "DERSequence.h"
#include "ECAlgorithms.h"
#include "ECCurve.h"
#include "ECFieldElement.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "X9Curve.h"
#include "X9FieldElement.h"
#include "X9FieldID.h"
#include "X9ObjectIdentifiers.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1X9X9Curve () {
 @public
  LibOrgBouncycastleMathEcECCurve *curve_;
  IOSByteArray *seed_;
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *fieldIdentifier_;
}

- (void)setFieldIdentifier;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9X9Curve, curve_, LibOrgBouncycastleMathEcECCurve *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9X9Curve, seed_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9X9Curve, fieldIdentifier_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X9X9Curve_setFieldIdentifier(LibOrgBouncycastleAsn1X9X9Curve *self);

@implementation LibOrgBouncycastleAsn1X9X9Curve

- (instancetype)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve {
  LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleMathEcECCurve_(self, curve);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleMathEcECCurve:(LibOrgBouncycastleMathEcECCurve *)curve
                                          withByteArray:(IOSByteArray *)seed {
  LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleMathEcECCurve_withByteArray_(self, curve, seed);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X9X9FieldID:(LibOrgBouncycastleAsn1X9X9FieldID *)fieldID
                                   withJavaMathBigInteger:(JavaMathBigInteger *)order
                                   withJavaMathBigInteger:(JavaMathBigInteger *)cofactor
                   withLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleAsn1X9X9FieldID_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1ASN1Sequence_(self, fieldID, order, cofactor, seq);
  return self;
}

- (void)setFieldIdentifier {
  LibOrgBouncycastleAsn1X9X9Curve_setFieldIdentifier(self);
}

- (LibOrgBouncycastleMathEcECCurve *)getCurve {
  return curve_;
}

- (IOSByteArray *)getSeed {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(seed_);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(fieldIdentifier_)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, prime_field)]) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:[new_LibOrgBouncycastleAsn1X9X9FieldElement_initWithLibOrgBouncycastleMathEcECFieldElement_([((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve_)) getA]) toASN1Primitive]];
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:[new_LibOrgBouncycastleAsn1X9X9FieldElement_initWithLibOrgBouncycastleMathEcECFieldElement_([((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve_)) getB]) toASN1Primitive]];
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(fieldIdentifier_)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, characteristic_two_field)]) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:[new_LibOrgBouncycastleAsn1X9X9FieldElement_initWithLibOrgBouncycastleMathEcECFieldElement_([((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve_)) getA]) toASN1Primitive]];
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:[new_LibOrgBouncycastleAsn1X9X9FieldElement_initWithLibOrgBouncycastleMathEcECFieldElement_([((LibOrgBouncycastleMathEcECCurve *) nil_chk(curve_)) getB]) toASN1Primitive]];
  }
  if (seed_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERBitString_initWithByteArray_(seed_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECCurve;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcECCurve:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleMathEcECCurve:withByteArray:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1X9X9FieldID:withJavaMathBigInteger:withJavaMathBigInteger:withLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(setFieldIdentifier);
  methods[4].selector = @selector(getCurve);
  methods[5].selector = @selector(getSeed);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "curve_", "LLibOrgBouncycastleMathEcECCurve;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "seed_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "fieldIdentifier_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleMathEcECCurve;", "LLibOrgBouncycastleMathEcECCurve;[B", "LLibOrgBouncycastleAsn1X9X9FieldID;LJavaMathBigInteger;LJavaMathBigInteger;LLibOrgBouncycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X9X9Curve = { "X9Curve", "lib.org.bouncycastle.asn1.x9", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X9X9Curve;
}

@end

void LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleMathEcECCurve_(LibOrgBouncycastleAsn1X9X9Curve *self, LibOrgBouncycastleMathEcECCurve *curve) {
  LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleMathEcECCurve_withByteArray_(self, curve, nil);
}

LibOrgBouncycastleAsn1X9X9Curve *new_LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleMathEcECCurve_(LibOrgBouncycastleMathEcECCurve *curve) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X9Curve, initWithLibOrgBouncycastleMathEcECCurve_, curve)
}

LibOrgBouncycastleAsn1X9X9Curve *create_LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleMathEcECCurve_(LibOrgBouncycastleMathEcECCurve *curve) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X9Curve, initWithLibOrgBouncycastleMathEcECCurve_, curve)
}

void LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleMathEcECCurve_withByteArray_(LibOrgBouncycastleAsn1X9X9Curve *self, LibOrgBouncycastleMathEcECCurve *curve, IOSByteArray *seed) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->fieldIdentifier_ = nil;
  self->curve_ = curve;
  self->seed_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(seed);
  LibOrgBouncycastleAsn1X9X9Curve_setFieldIdentifier(self);
}

LibOrgBouncycastleAsn1X9X9Curve *new_LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleMathEcECCurve_withByteArray_(LibOrgBouncycastleMathEcECCurve *curve, IOSByteArray *seed) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X9Curve, initWithLibOrgBouncycastleMathEcECCurve_withByteArray_, curve, seed)
}

LibOrgBouncycastleAsn1X9X9Curve *create_LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleMathEcECCurve_withByteArray_(LibOrgBouncycastleMathEcECCurve *curve, IOSByteArray *seed) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X9Curve, initWithLibOrgBouncycastleMathEcECCurve_withByteArray_, curve, seed)
}

void LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleAsn1X9X9FieldID_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X9X9Curve *self, LibOrgBouncycastleAsn1X9X9FieldID *fieldID, JavaMathBigInteger *order, JavaMathBigInteger *cofactor, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->fieldIdentifier_ = nil;
  self->fieldIdentifier_ = [((LibOrgBouncycastleAsn1X9X9FieldID *) nil_chk(fieldID)) getIdentifier];
  if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(self->fieldIdentifier_)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, prime_field)]) {
    JavaMathBigInteger *p = [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(((LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([fieldID getParameters], [LibOrgBouncycastleAsn1ASN1Integer class])))) getValue];
    JavaMathBigInteger *A = new_JavaMathBigInteger_initWithInt_withByteArray_(1, [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]))) getOctets]);
    JavaMathBigInteger *B = new_JavaMathBigInteger_initWithInt_withByteArray_(1, [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:1]))) getOctets]);
    self->curve_ = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(p, A, B, order, cofactor);
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(self->fieldIdentifier_)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, characteristic_two_field)]) {
    LibOrgBouncycastleAsn1ASN1Sequence *parameters = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([fieldID getParameters]);
    jint m = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(((LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(parameters)) getObjectAtWithInt:0], [LibOrgBouncycastleAsn1ASN1Integer class])))) getValue])) intValue];
    LibOrgBouncycastleAsn1ASN1ObjectIdentifier *representation = (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) cast_chk([parameters getObjectAtWithInt:1], [LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]);
    jint k1 = 0;
    jint k2 = 0;
    jint k3 = 0;
    if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(representation)) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, tpBasis)]) {
      k1 = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([parameters getObjectAtWithInt:2]))) getValue])) intValue];
    }
    else if ([representation isEqual:JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, ppBasis)]) {
      LibOrgBouncycastleAsn1ASN1Sequence *pentanomial = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([parameters getObjectAtWithInt:2]);
      k1 = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(pentanomial)) getObjectAtWithInt:0]))) getValue])) intValue];
      k2 = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([pentanomial getObjectAtWithInt:1]))) getValue])) intValue];
      k3 = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([pentanomial getObjectAtWithInt:2]))) getValue])) intValue];
    }
    else {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"This type of EC basis is not implemented");
    }
    JavaMathBigInteger *A = new_JavaMathBigInteger_initWithInt_withByteArray_(1, [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]))) getOctets]);
    JavaMathBigInteger *B = new_JavaMathBigInteger_initWithInt_withByteArray_(1, [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:1]))) getOctets]);
    self->curve_ = new_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_(m, k1, k2, k3, A, B, order, cofactor);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"This type of ECCurve is not implemented");
  }
  if ([seq size] == 3) {
    self->seed_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_([((LibOrgBouncycastleAsn1DERBitString *) nil_chk(((LibOrgBouncycastleAsn1DERBitString *) cast_chk([seq getObjectAtWithInt:2], [LibOrgBouncycastleAsn1DERBitString class])))) getBytes]);
  }
}

LibOrgBouncycastleAsn1X9X9Curve *new_LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleAsn1X9X9FieldID_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X9X9FieldID *fieldID, JavaMathBigInteger *order, JavaMathBigInteger *cofactor, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9X9Curve, initWithLibOrgBouncycastleAsn1X9X9FieldID_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1ASN1Sequence_, fieldID, order, cofactor, seq)
}

LibOrgBouncycastleAsn1X9X9Curve *create_LibOrgBouncycastleAsn1X9X9Curve_initWithLibOrgBouncycastleAsn1X9X9FieldID_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X9X9FieldID *fieldID, JavaMathBigInteger *order, JavaMathBigInteger *cofactor, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9X9Curve, initWithLibOrgBouncycastleAsn1X9X9FieldID_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1ASN1Sequence_, fieldID, order, cofactor, seq)
}

void LibOrgBouncycastleAsn1X9X9Curve_setFieldIdentifier(LibOrgBouncycastleAsn1X9X9Curve *self) {
  if (LibOrgBouncycastleMathEcECAlgorithms_isFpCurveWithLibOrgBouncycastleMathEcECCurve_(self->curve_)) {
    self->fieldIdentifier_ = JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, prime_field);
  }
  else if (LibOrgBouncycastleMathEcECAlgorithms_isF2mCurveWithLibOrgBouncycastleMathEcECCurve_(self->curve_)) {
    self->fieldIdentifier_ = JreLoadStatic(LibOrgBouncycastleAsn1X9X9ObjectIdentifiers, characteristic_two_field);
  }
  else {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"This type of ECCurve is not implemented");
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X9X9Curve)
