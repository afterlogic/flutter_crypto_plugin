//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/tsp/Accuracy.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Integer.h"
#include "ASN1Object.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "ASN1TaggedObject.h"
#include "Accuracy.h"
#include "DERSequence.h"
#include "DERTaggedObject.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleAsn1TspAccuracy ()

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq;

@end

__attribute__((unused)) static void LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1TspAccuracy *self, LibOrgBouncycastleAsn1ASN1Sequence *seq);

__attribute__((unused)) static LibOrgBouncycastleAsn1TspAccuracy *new_LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1TspAccuracy *create_LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq);

@implementation LibOrgBouncycastleAsn1TspAccuracy

+ (jint)MIN_MILLIS {
  return LibOrgBouncycastleAsn1TspAccuracy_MIN_MILLIS;
}

+ (jint)MAX_MILLIS {
  return LibOrgBouncycastleAsn1TspAccuracy_MAX_MILLIS;
}

+ (jint)MIN_MICROS {
  return LibOrgBouncycastleAsn1TspAccuracy_MIN_MICROS;
}

+ (jint)MAX_MICROS {
  return LibOrgBouncycastleAsn1TspAccuracy_MAX_MICROS;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1TspAccuracy_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)seconds
                    withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)millis
                    withLibOrgBouncycastleAsn1ASN1Integer:(LibOrgBouncycastleAsn1ASN1Integer *)micros {
  LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(self, seconds, millis, micros);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1Sequence:(LibOrgBouncycastleAsn1ASN1Sequence *)seq {
  LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Sequence_(self, seq);
  return self;
}

+ (LibOrgBouncycastleAsn1TspAccuracy *)getInstanceWithId:(id)o {
  return LibOrgBouncycastleAsn1TspAccuracy_getInstanceWithId_(o);
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getSeconds {
  return seconds_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getMillis {
  return millis_;
}

- (LibOrgBouncycastleAsn1ASN1Integer *)getMicros {
  return micros_;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if (seconds_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:seconds_];
  }
  if (millis_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 0, millis_)];
  }
  if (micros_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERTaggedObject_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, 1, micros_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1TspAccuracy;", 0x9, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Integer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1ASN1Integer:withLibOrgBouncycastleAsn1ASN1Integer:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1Sequence:);
  methods[3].selector = @selector(getInstanceWithId:);
  methods[4].selector = @selector(getSeconds);
  methods[5].selector = @selector(getMillis);
  methods[6].selector = @selector(getMicros);
  methods[7].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "seconds_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "millis_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "micros_", "LLibOrgBouncycastleAsn1ASN1Integer;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "MIN_MILLIS", "I", .constantValue.asInt = LibOrgBouncycastleAsn1TspAccuracy_MIN_MILLIS, 0x1c, -1, -1, -1, -1 },
    { "MAX_MILLIS", "I", .constantValue.asInt = LibOrgBouncycastleAsn1TspAccuracy_MAX_MILLIS, 0x1c, -1, -1, -1, -1 },
    { "MIN_MICROS", "I", .constantValue.asInt = LibOrgBouncycastleAsn1TspAccuracy_MIN_MICROS, 0x1c, -1, -1, -1, -1 },
    { "MAX_MICROS", "I", .constantValue.asInt = LibOrgBouncycastleAsn1TspAccuracy_MAX_MICROS, 0x1c, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1ASN1Integer;LLibOrgBouncycastleAsn1ASN1Integer;", "LLibOrgBouncycastleAsn1ASN1Sequence;", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1TspAccuracy = { "Accuracy", "lib.org.bouncycastle.asn1.tsp", ptrTable, methods, fields, 7, 0x1, 8, 7, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1TspAccuracy;
}

@end

void LibOrgBouncycastleAsn1TspAccuracy_init(LibOrgBouncycastleAsn1TspAccuracy *self) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
}

LibOrgBouncycastleAsn1TspAccuracy *new_LibOrgBouncycastleAsn1TspAccuracy_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1TspAccuracy, init)
}

LibOrgBouncycastleAsn1TspAccuracy *create_LibOrgBouncycastleAsn1TspAccuracy_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1TspAccuracy, init)
}

void LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1TspAccuracy *self, LibOrgBouncycastleAsn1ASN1Integer *seconds, LibOrgBouncycastleAsn1ASN1Integer *millis, LibOrgBouncycastleAsn1ASN1Integer *micros) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->seconds_ = seconds;
  if (millis != nil && ([((JavaMathBigInteger *) nil_chk([millis getValue])) intValue] < LibOrgBouncycastleAsn1TspAccuracy_MIN_MILLIS || [((JavaMathBigInteger *) nil_chk([millis getValue])) intValue] > LibOrgBouncycastleAsn1TspAccuracy_MAX_MILLIS)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Invalid millis field : not in (1..999)");
  }
  else {
    self->millis_ = millis;
  }
  if (micros != nil && ([((JavaMathBigInteger *) nil_chk([micros getValue])) intValue] < LibOrgBouncycastleAsn1TspAccuracy_MIN_MICROS || [((JavaMathBigInteger *) nil_chk([micros getValue])) intValue] > LibOrgBouncycastleAsn1TspAccuracy_MAX_MICROS)) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Invalid micros field : not in (1..999)");
  }
  else {
    self->micros_ = micros;
  }
}

LibOrgBouncycastleAsn1TspAccuracy *new_LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *seconds, LibOrgBouncycastleAsn1ASN1Integer *millis, LibOrgBouncycastleAsn1ASN1Integer *micros) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1TspAccuracy, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_, seconds, millis, micros)
}

LibOrgBouncycastleAsn1TspAccuracy *create_LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(LibOrgBouncycastleAsn1ASN1Integer *seconds, LibOrgBouncycastleAsn1ASN1Integer *millis, LibOrgBouncycastleAsn1ASN1Integer *micros) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1TspAccuracy, initWithLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_, seconds, millis, micros)
}

void LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1TspAccuracy *self, LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->seconds_ = nil;
  self->millis_ = nil;
  self->micros_ = nil;
  for (jint i = 0; i < [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) size]; i++) {
    if ([[seq getObjectAtWithInt:i] isKindOfClass:[LibOrgBouncycastleAsn1ASN1Integer class]]) {
      self->seconds_ = (LibOrgBouncycastleAsn1ASN1Integer *) cast_chk([seq getObjectAtWithInt:i], [LibOrgBouncycastleAsn1ASN1Integer class]);
    }
    else if ([[seq getObjectAtWithInt:i] isKindOfClass:[LibOrgBouncycastleAsn1ASN1TaggedObject class]]) {
      LibOrgBouncycastleAsn1ASN1TaggedObject *extra = (LibOrgBouncycastleAsn1ASN1TaggedObject *) cast_chk([seq getObjectAtWithInt:i], [LibOrgBouncycastleAsn1ASN1TaggedObject class]);
      switch ([((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(extra)) getTagNo]) {
        case 0:
        self->millis_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(extra, false);
        if ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(self->millis_)) getValue])) intValue] < LibOrgBouncycastleAsn1TspAccuracy_MIN_MILLIS || [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(self->millis_)) getValue])) intValue] > LibOrgBouncycastleAsn1TspAccuracy_MAX_MILLIS) {
          @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Invalid millis field : not in (1..999).");
        }
        break;
        case 1:
        self->micros_ = LibOrgBouncycastleAsn1ASN1Integer_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(extra, false);
        if ([((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(self->micros_)) getValue])) intValue] < LibOrgBouncycastleAsn1TspAccuracy_MIN_MICROS || [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleAsn1ASN1Integer *) nil_chk(self->micros_)) getValue])) intValue] > LibOrgBouncycastleAsn1TspAccuracy_MAX_MICROS) {
          @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Invalid micros field : not in (1..999).");
        }
        break;
        default:
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Invalig tag number");
      }
    }
  }
}

LibOrgBouncycastleAsn1TspAccuracy *new_LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1TspAccuracy, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1TspAccuracy *create_LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence *seq) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1TspAccuracy, initWithLibOrgBouncycastleAsn1ASN1Sequence_, seq)
}

LibOrgBouncycastleAsn1TspAccuracy *LibOrgBouncycastleAsn1TspAccuracy_getInstanceWithId_(id o) {
  LibOrgBouncycastleAsn1TspAccuracy_initialize();
  if ([o isKindOfClass:[LibOrgBouncycastleAsn1TspAccuracy class]]) {
    return (LibOrgBouncycastleAsn1TspAccuracy *) o;
  }
  if (o != nil) {
    return new_LibOrgBouncycastleAsn1TspAccuracy_initWithLibOrgBouncycastleAsn1ASN1Sequence_(LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(o));
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1TspAccuracy)
