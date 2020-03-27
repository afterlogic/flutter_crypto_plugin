//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x9/DHDomainParameters.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERSequence.h"
#include "DHDomainParameters.h"
#include "DHValidationParms.h"
#include "IOSClass.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1X9DHDomainParameters () {
 @public
  LibOrgBouncycastleAsn1ASN1Integer *p_;
  LibOrgBouncycastleAsn1ASN1Integer *g_;
  LibOrgBouncycastleAsn1ASN1Integer *q_;
  LibOrgBouncycastleAsn1ASN1Integer *j_;
  LibOrgBouncycastleAsn1X9DHValidationParms *validationParms_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

+ (id<LibOrgBouncycastleAsn1ASN1Encodable>)getNextWithJavaUtilEnumeration:(id<JavaUtilEnumeration>)e;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9DHDomainParameters, p_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9DHDomainParameters, g_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9DHDomainParameters, q_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9DHDomainParameters, j_, LibOrgBouncycastleAsn1ASN1Integer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9DHDomainParameters, validationParms_, LibOrgBouncycastleAsn1X9DHValidationParms *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X9DHDomainParameters *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X9DHDomainParameters *new_LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X9DHDomainParameters *create_LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static id<LibOrgBouncycastleAsn1ASN1Encodable> LibOrgBouncycastleAsn1X9DHDomainParameters_getNextWithJavaUtilEnumeration_(id<JavaUtilEnumeration> e);

@implementation LibOrgBouncycastleAsn1X9DHDomainParameters

+ (LibOrgBouncycastleAsn1X9DHDomainParameters *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                          withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1X9DHDomainParameters_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1X9DHDomainParameters *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X9DHDomainParameters_getInstanceWithId_(obj);
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)p
                    withJavaMathBigInteger:(JavaMathBigInteger *)g
                    withJavaMathBigInteger:(JavaMathBigInteger *)q
                    withJavaMathBigInteger:(JavaMathBigInteger *)j
withLibOrgBouncycastleAsn1X9DHValidationParms:(LibOrgBouncycastleAsn1X9DHValidationParms *)validationParms {
  LibOrgBouncycastleAsn1X9DHDomainParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1X9DHValidationParms_(self, p, g, q, j, validationParms);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)p
                    withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)g
                    withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)q
                    withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)j
            withLibOrgBouncycastleAsn1X9DHValidationParms:(LibOrgBouncycastleAsn1X9DHValidationParms *)validationParms {
  LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X9DHValidationParms_(self, p, g, q, j, validationParms);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (id<LibOrgBouncycastleAsn1ASN1Encodable>)getNextWithJavaUtilEnumeration:(id<JavaUtilEnumeration>)e {
  return LibOrgBouncycastleAsn1X9DHDomainParameters_getNextWithJavaUtilEnumeration_(e);
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getP {
  return self->p_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getG {
  return self->g_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getQ {
  return self->q_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getJ {
  return self->j_;
}

- (LibOrgBouncycastleAsn1X9DHValidationParms *)getValidationParms {
  return self->validationParms_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:self->p_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:self->g_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:self->q_];
  if (self->j_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:self->j_];
  }
  if (self->validationParms_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:self->validationParms_];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X9DHDomainParameters;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X9DHDomainParameters;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0xa, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X9DHValidationParms;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withJavaMathBigInteger:withLibOrgBouncycastleAsn1X9DHValidationParms:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1X9DHValidationParms:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[5].selector = @selector(getNextWithJavaUtilEnumeration:);
  methods[6].selector = @selector(getP);
  methods[7].selector = @selector(getG);
  methods[8].selector = @selector(getQ);
  methods[9].selector = @selector(getJ);
  methods[10].selector = @selector(getValidationParms);
  methods[11].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "p_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "g_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "q_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "j_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "validationParms_", "LLibOrgBouncycastleAsn1X9DHValidationParms;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LJavaMathBigInteger;LLibOrgBouncycastleAsn1X9DHValidationParms;", "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1X9DHValidationParms;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getNext", "LJavaUtilEnumeration;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X9DHDomainParameters = { "DHDomainParameters", "lib.org.bouncycastle.asn1.x9", ptrTable, methods, fields, 7, 0x1, 12, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X9DHDomainParameters;
}

@end

LibOrgBouncycastleAsn1X9DHDomainParameters *LibOrgBouncycastleAsn1X9DHDomainParameters_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1X9DHDomainParameters_initialize();
  return LibOrgBouncycastleAsn1X9DHDomainParameters_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1X9DHDomainParameters *LibOrgBouncycastleAsn1X9DHDomainParameters_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X9DHDomainParameters_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1X9DHDomainParameters class]]) {
    return (LibOrgBouncycastleAsn1X9DHDomainParameters *) cast_chk(obj, [LibOrgBouncycastleAsn1X9DHDomainParameters class]);
  }
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1Sequence class]]) {
    return new_LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_((LibOrgBouncycastleAsn1ASN1Sequence *) obj);
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"Invalid DHDomainParameters: ", [[obj java_getClass] getName]));
}

void LibOrgBouncycastleAsn1X9DHDomainParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1X9DHValidationParms_(LibOrgBouncycastleAsn1X9DHDomainParameters *self, JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, JavaMathBigInteger *j, LibOrgBouncycastleAsn1X9DHValidationParms *validationParms) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (p == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'p' cannot be null");
  }
  if (g == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'g' cannot be null");
  }
  if (q == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'q' cannot be null");
  }
  self->p_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(p);
  self->g_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(g);
  self->q_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(q);
  self->j_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithJavaMathBigInteger_(j);
  self->validationParms_ = validationParms;
}

LibOrgBouncycastleAsn1X9DHDomainParameters *new_LibOrgBouncycastleAsn1X9DHDomainParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1X9DHValidationParms_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, JavaMathBigInteger *j, LibOrgBouncycastleAsn1X9DHValidationParms *validationParms) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9DHDomainParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1X9DHValidationParms_, p, g, q, j, validationParms)
}

LibOrgBouncycastleAsn1X9DHDomainParameters *create_LibOrgBouncycastleAsn1X9DHDomainParameters_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1X9DHValidationParms_(JavaMathBigInteger *p, JavaMathBigInteger *g, JavaMathBigInteger *q, JavaMathBigInteger *j, LibOrgBouncycastleAsn1X9DHValidationParms *validationParms) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9DHDomainParameters, initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleAsn1X9DHValidationParms_, p, g, q, j, validationParms)
}

void LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X9DHValidationParms_(LibOrgBouncycastleAsn1X9DHDomainParameters *self, LibOrgBouncycastleAsn1ASN1Integer *p, LibOrgBouncycastleAsn1ASN1Integer *g, LibOrgBouncycastleAsn1ASN1Integer *q, LibOrgBouncycastleAsn1ASN1Integer *j, LibOrgBouncycastleAsn1X9DHValidationParms *validationParms) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (p == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'p' cannot be null");
  }
  if (g == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'g' cannot be null");
  }
  if (q == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'q' cannot be null");
  }
  self->p_ = p;
  self->g_ = g;
  self->q_ = q;
  self->j_ = j;
  self->validationParms_ = validationParms;
}

LibOrgBouncycastleAsn1X9DHDomainParameters *new_LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X9DHValidationParms_(LibOrgBouncycastleAsn1ASN1Integer *p, LibOrgBouncycastleAsn1ASN1Integer *g, LibOrgBouncycastleAsn1ASN1Integer *q, LibOrgBouncycastleAsn1ASN1Integer *j, LibOrgBouncycastleAsn1X9DHValidationParms *validationParms) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9DHDomainParameters, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X9DHValidationParms_, p, g, q, j, validationParms)
}

LibOrgBouncycastleAsn1X9DHDomainParameters *create_LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X9DHValidationParms_(LibOrgBouncycastleAsn1ASN1Integer *p, LibOrgBouncycastleAsn1ASN1Integer *g, LibOrgBouncycastleAsn1ASN1Integer *q, LibOrgBouncycastleAsn1ASN1Integer *j, LibOrgBouncycastleAsn1X9DHValidationParms *validationParms) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9DHDomainParameters, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1X9DHValidationParms_, p, g, q, j, validationParms)
}

void LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X9DHDomainParameters *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] < 3 || [seq size] > 5) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  id<JavaUtilEnumeration> e = [seq getObjects];
  self->p_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([((id<JavaUtilEnumeration>) nil_chk(e)) nextElement]);
  self->g_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([e nextElement]);
  self->q_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([e nextElement]);
  id<LibOrgBouncycastleAsn1ASN1Encodable> next = LibOrgBouncycastleAsn1X9DHDomainParameters_getNextWithJavaUtilEnumeration_(e);
  if (next != nil && [next isKindOfClass:[LibOrgBouncycastleAsn1ASN1Integer class]]) {
    self->j_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_(next);
    next = LibOrgBouncycastleAsn1X9DHDomainParameters_getNextWithJavaUtilEnumeration_(e);
  }
  if (next != nil) {
    self->validationParms_ = LibOrgBouncycastleAsn1X9DHValidationParms_getInstanceWithId_([next toASN1Primitive]);
  }
}

LibOrgBouncycastleAsn1X9DHDomainParameters *new_LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9DHDomainParameters, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X9DHDomainParameters *create_LibOrgBouncycastleAsn1X9DHDomainParameters_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9DHDomainParameters, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

id<LibOrgBouncycastleAsn1ASN1Encodable> LibOrgBouncycastleAsn1X9DHDomainParameters_getNextWithJavaUtilEnumeration_(id<JavaUtilEnumeration> e) {
  LibOrgBouncycastleAsn1X9DHDomainParameters_initialize();
  return [((id<JavaUtilEnumeration>) nil_chk(e)) hasMoreElements] ? (id<LibOrgBouncycastleAsn1ASN1Encodable>) cast_check([e nextElement], LibOrgBouncycastleAsn1ASN1Encodable_class_()) : nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X9DHDomainParameters)
