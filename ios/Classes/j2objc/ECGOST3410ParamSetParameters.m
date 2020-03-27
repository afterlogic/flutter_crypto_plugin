//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/cryptopro/ECGOST3410ParamSetParameters.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "ECGOST3410ParamSetParameters.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"

@implementation LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters

+ (LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                                           withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_getInstanceWithId_(obj);
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)a
                    withJavaMathBigInteger:(JavaMathBigInteger *)b
                    withJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                                   withInt:(jint)x
                    withJavaMathBigInteger:(JavaMathBigInteger *)y {
  LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_(self, a, b, p, q, x, y);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (JavaMathBigInteger *)getP {
  return [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(p_)) getPositiveValue];
}

- (JavaMathBigInteger *)getQ {
  return [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(q_)) getPositiveValue];
}

- (JavaMathBigInteger *)getA {
  return [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(a_)) getPositiveValue];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:a_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:b_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:p_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:q_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:x_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:y_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withInt:withJavaMathBigInteger:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[4].selector = @selector(getP);
  methods[5].selector = @selector(getQ);
  methods[6].selector = @selector(getA);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "p_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "q_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "a_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "b_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "x_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "y_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;ILJavaMathBigInteger;", "LLibOrgBouncycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters = { "ECGOST3410ParamSetParameters", "lib.org.bouncycastle.asn1.cryptopro", ptrTable, methods, fields, 7, 0x1, 8, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters;
}

@end

LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initialize();
  return LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters class]]) {
    return (LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *) cast_chk(obj, [LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters class]);
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_((LibOrgBouncycastleAsn1ASN1Sequence *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid GOST3410Parameter: ", [[obj java_getClass] getName]));
}

void LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_(LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *self, JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *p, JavaMathBigInteger *q, jint x, JavaMathBigInteger *y) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->a_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(a);
  self->b_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(b);
  self->p_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(p);
  self->q_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(q);
  self->x_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(x);
  self->y_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(y);
}

LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *new_LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_(JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *p, JavaMathBigInteger *q, jint x, JavaMathBigInteger *y) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_, a, b, p, q, x, y)
}

LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *create_LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_(JavaMathBigInteger *a, JavaMathBigInteger *b, JavaMathBigInteger *p, JavaMathBigInteger *q, jint x, JavaMathBigInteger *y) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withInt_withJavaMathBigInteger_, a, b, p, q, x, y)
}

void LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->a_ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement], [LibOrgBouncycastleAsn1ASN1Integer class]);
  self->b_ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1Integer class]);
  self->p_ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1Integer class]);
  self->q_ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1Integer class]);
  self->x_ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1Integer class]);
  self->y_ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1Integer class]);
}

LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *new_LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters *create_LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1CryptoproECGOST3410ParamSetParameters)
