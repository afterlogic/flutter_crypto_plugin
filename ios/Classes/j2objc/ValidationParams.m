//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x9/ValidationParams.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "DERBitString.h"
#include "DERSequence.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ValidationParams.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1X9ValidationParams () {
 @public
  LibOrgBouncycastleAsn1DERBitString *seed_;
  LibOrgBouncycastleAsn1ASN1Integer *pgenCounter_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9ValidationParams, seed_, LibOrgBouncycastleAsn1DERBitString *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1X9ValidationParams, pgenCounter_, LibOrgBouncycastleAsn1ASN1Integer *)

__attribute__((unused)) static void LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X9ValidationParams *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1X9ValidationParams *new_LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1X9ValidationParams *create_LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1X9ValidationParams

+ (LibOrgBouncycastleAsn1X9ValidationParams *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                        withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1X9ValidationParams_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

+ (LibOrgBouncycastleAsn1X9ValidationParams *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1X9ValidationParams_getInstanceWithId_(obj);
}

- (instancetype)initWithByteArray:(IOSByteArray *)seed
                          withInt:(jint)pgenCounter {
  LibOrgBouncycastleAsn1X9ValidationParams_initWithByteArray_withInt_(self, seed, pgenCounter);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1DERBitString:(LibOrgBouncycastleAsn1DERBitString *)seed
                     withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)pgenCounter {
  LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Integer_(self, seed, pgenCounter);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

- (IOSByteArray *)getSeed {
  return [((LibOrgBouncycastleAsn1DERBitString *) nil_chk(self->seed_)) getBytes];
}

- (JavaMathBigInteger *)getPgenCounter {
  return [((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(self->pgenCounter_)) getPositiveValue];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:self->seed_];
  [v addWithLibOrgBouncycastleAsn1ASN1Encodable:self->pgenCounter_];
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1X9ValidationParams;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1X9ValidationParams;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[1].selector = @selector(getInstanceWithId:);
  methods[2].selector = @selector(initWithByteArray:withInt:);
  methods[3].selector = @selector(initWithLibOrgBouncycastleAsn1DERBitString:withLibOrgBouncycastleAsn1ASN1Integer:);
  methods[4].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[5].selector = @selector(getSeed);
  methods[6].selector = @selector(getPgenCounter);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "seed_", "LLibOrgBouncycastleAsn1DERBitString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "pgenCounter_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSObject;", "[BI", "LLibOrgBouncycastleAsn1DERBitString;LLibOrgBouncycastleAsn1ASN1Integer;", "LLibOrgBouncycastleAsn1ASN1Sequence;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X9ValidationParams = { "ValidationParams", "lib.org.bouncycastle.asn1.x9", ptrTable, methods, fields, 7, 0x1, 8, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X9ValidationParams;
}

@end

LibOrgBouncycastleAsn1X9ValidationParams *LibOrgBouncycastleAsn1X9ValidationParams_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1X9ValidationParams_initialize();
  return LibOrgBouncycastleAsn1X9ValidationParams_getInstanceWithId_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_));
}

LibOrgBouncycastleAsn1X9ValidationParams *LibOrgBouncycastleAsn1X9ValidationParams_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1X9ValidationParams_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1X9ValidationParams class]]) {
    return (LibOrgBouncycastleAsn1X9ValidationParams *) obj;
  }
  else if (obj != nil) {
    return new_LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj));
  }
  return nil;
}

void LibOrgBouncycastleAsn1X9ValidationParams_initWithByteArray_withInt_(LibOrgBouncycastleAsn1X9ValidationParams *self, IOSByteArray *seed, jint pgenCounter) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (seed == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'seed' cannot be null");
  }
  self->seed_ = new_LibOrgBouncycastleAsn1DERBitString_initWithByteArray_(seed);
  self->pgenCounter_ = new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_(pgenCounter);
}

LibOrgBouncycastleAsn1X9ValidationParams *new_LibOrgBouncycastleAsn1X9ValidationParams_initWithByteArray_withInt_(IOSByteArray *seed, jint pgenCounter) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9ValidationParams, initWithByteArray_withInt_, seed, pgenCounter)
}

LibOrgBouncycastleAsn1X9ValidationParams *create_LibOrgBouncycastleAsn1X9ValidationParams_initWithByteArray_withInt_(IOSByteArray *seed, jint pgenCounter) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9ValidationParams, initWithByteArray_withInt_, seed, pgenCounter)
}

void LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1X9ValidationParams *self, LibOrgBouncycastleAsn1DERBitString *seed, LibOrgBouncycastleAsn1ASN1Integer *pgenCounter) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if (seed == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'seed' cannot be null");
  }
  if (pgenCounter == nil) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'pgenCounter' cannot be null");
  }
  self->seed_ = seed;
  self->pgenCounter_ = pgenCounter;
}

LibOrgBouncycastleAsn1X9ValidationParams *new_LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1DERBitString *seed, LibOrgBouncycastleAsn1ASN1Integer *pgenCounter) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9ValidationParams, initWithLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Integer_, seed, pgenCounter)
}

LibOrgBouncycastleAsn1X9ValidationParams *create_LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1DERBitString *seed, LibOrgBouncycastleAsn1ASN1Integer *pgenCounter) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9ValidationParams, initWithLibOrgBouncycastleAsn1DERBitString_withLibOrgBouncycastleAsn1ASN1Integer_, seed, pgenCounter)
}

void LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1X9ValidationParams *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  if ([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size] != 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$I", @"Bad sequence size: ", [seq size]));
  }
  self->seed_ = LibOrgBouncycastleAsn1DERBitString_getInstanceWithId_([seq getObjectAtWithInt:0]);
  self->pgenCounter_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithId_([seq getObjectAtWithInt:1]);
}

LibOrgBouncycastleAsn1X9ValidationParams *new_LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1X9ValidationParams, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1X9ValidationParams *create_LibOrgBouncycastleAsn1X9ValidationParams_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1X9ValidationParams, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X9ValidationParams)
