//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/pkcs/DHParameter.java
//

#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "DERSequence.h"
#include "DHParameter.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1PkcsDHParameter ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1PkcsDHParameter_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1PkcsDHParameter *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1PkcsDHParameter *new_LibOrgBouncycastleAsn1PkcsDHParameter_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1PkcsDHParameter *create_LibOrgBouncycastleAsn1PkcsDHParameter_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1PkcsDHParameter

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)g
                                   withInt:(jint)l {
  LibOrgBouncycastleAsn1PkcsDHParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_(self, p, g, l);
  return self;
}

+ (LibOrgBouncycastleAsn1PkcsDHParameter *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1PkcsDHParameter_getInstanceWithId_(obj);
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1PkcsDHParameter_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (JavaMathBigInteger *)getP {
  return [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(p_)) getPositiveValue];
}

- (JavaMathBigInteger *)getG {
  return [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(g_)) getPositiveValue];
}

- (JavaMathBigInteger *)getL {
  if (l_ == nil) {
    return nil;
  }
  return [l_ getPositiveValue];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:p_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:g_];
  if ([self getL] != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:l_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1PkcsDHParameter;", 0x9, 1, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 3, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withInt:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getP);
  methods[4].selector = @selector(getG);
  methods[5].selector = @selector(getL);
  methods[6].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "p_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "g_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "l_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LJavaMathBigInteger;I", "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1PkcsDHParameter = { "DHParameter", "lib.org.bouncycastle.asn1.pkcs", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1PkcsDHParameter;
}

@end

void LibOrgBouncycastleAsn1PkcsDHParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_(LibOrgBouncycastleAsn1PkcsDHParameter *self, JavaMathBigInteger *p, JavaMathBigInteger *g, jint l) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->p_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(p);
  self->g_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(g);
  if (l != 0) {
    self->l_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(l);
  }
  else {
    self->l_ = nil;
  }
}

LibOrgBouncycastleAsn1PkcsDHParameter *new_LibOrgBouncycastleAsn1PkcsDHParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_(JavaMathBigInteger *p, JavaMathBigInteger *g, jint l) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1PkcsDHParameter, initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_, p, g, l)
}

LibOrgBouncycastleAsn1PkcsDHParameter *create_LibOrgBouncycastleAsn1PkcsDHParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_(JavaMathBigInteger *p, JavaMathBigInteger *g, jint l) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1PkcsDHParameter, initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_, p, g, l)
}

LibOrgBouncycastleAsn1PkcsDHParameter *LibOrgBouncycastleAsn1PkcsDHParameter_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1PkcsDHParameter_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1PkcsDHParameter class]]) {
    return (LibOrgBouncycastleAsn1PkcsDHParameter *) obj;
  }
  if (obj != nil) {
    return new_LibOrgBouncycastleAsn1PkcsDHParameter_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1PkcsDHParameter_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1PkcsDHParameter *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  id<JavaUtilEnumeration> e = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects];
  self->p_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement]);
  self->g_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([e nextElement]);
  if ([e hasMoreElements]) {
    self->l_ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([e nextElement], [LibOrgBouncycastleAsn1ASN1Integer class]);
  }
  else {
    self->l_ = nil;
  }
}

LibOrgBouncycastleAsn1PkcsDHParameter *new_LibOrgBouncycastleAsn1PkcsDHParameter_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1PkcsDHParameter, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1PkcsDHParameter *create_LibOrgBouncycastleAsn1PkcsDHParameter_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1PkcsDHParameter, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1PkcsDHParameter)
