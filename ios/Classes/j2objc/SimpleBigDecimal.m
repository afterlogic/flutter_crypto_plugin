//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/SimpleBigDecimal.java
//

#include "ECConstants.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "SimpleBigDecimal.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/StringBuffer.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleMathEcSimpleBigDecimal () {
 @public
  JavaMathBigInteger *bigInt_;
  jint scale__;
}

- (void)checkScaleWithLibOrgBouncycastleMathEcSimpleBigDecimal:(LibOrgBouncycastleMathEcSimpleBigDecimal *)b;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleMathEcSimpleBigDecimal, bigInt_, JavaMathBigInteger *)

inline jlong LibOrgBouncycastleMathEcSimpleBigDecimal_get_serialVersionUID(void);
#define LibOrgBouncycastleMathEcSimpleBigDecimal_serialVersionUID 1LL
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleMathEcSimpleBigDecimal, serialVersionUID, jlong)

__attribute__((unused)) static void LibOrgBouncycastleMathEcSimpleBigDecimal_checkScaleWithLibOrgBouncycastleMathEcSimpleBigDecimal_(LibOrgBouncycastleMathEcSimpleBigDecimal *self, LibOrgBouncycastleMathEcSimpleBigDecimal *b);

@implementation LibOrgBouncycastleMathEcSimpleBigDecimal

+ (LibOrgBouncycastleMathEcSimpleBigDecimal *)getInstanceWithJavaMathBigInteger:(JavaMathBigInteger *)value
                                                                        withInt:(jint)scale_ {
  return LibOrgBouncycastleMathEcSimpleBigDecimal_getInstanceWithJavaMathBigInteger_withInt_(value, scale_);
}

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)bigInt
                                   withInt:(jint)scale_ {
  LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(self, bigInt, scale_);
  return self;
}

- (void)checkScaleWithLibOrgBouncycastleMathEcSimpleBigDecimal:(LibOrgBouncycastleMathEcSimpleBigDecimal *)b {
  LibOrgBouncycastleMathEcSimpleBigDecimal_checkScaleWithLibOrgBouncycastleMathEcSimpleBigDecimal_(self, b);
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)adjustScaleWithInt:(jint)newScale {
  if (newScale < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"scale may not be negative");
  }
  if (newScale == scale__) {
    return self;
  }
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) shiftLeftWithInt:newScale - scale__], newScale);
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)addWithLibOrgBouncycastleMathEcSimpleBigDecimal:(LibOrgBouncycastleMathEcSimpleBigDecimal *)b {
  LibOrgBouncycastleMathEcSimpleBigDecimal_checkScaleWithLibOrgBouncycastleMathEcSimpleBigDecimal_(self, b);
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) addWithJavaMathBigInteger:((LibOrgBouncycastleMathEcSimpleBigDecimal *) nil_chk(b))->bigInt_], scale__);
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)addWithJavaMathBigInteger:(JavaMathBigInteger *)b {
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) addWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(b)) shiftLeftWithInt:scale__]], scale__);
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)negate {
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) negate], scale__);
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)subtractWithLibOrgBouncycastleMathEcSimpleBigDecimal:(LibOrgBouncycastleMathEcSimpleBigDecimal *)b {
  return [self addWithLibOrgBouncycastleMathEcSimpleBigDecimal:[((LibOrgBouncycastleMathEcSimpleBigDecimal *) nil_chk(b)) negate]];
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)subtractWithJavaMathBigInteger:(JavaMathBigInteger *)b {
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) subtractWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(b)) shiftLeftWithInt:scale__]], scale__);
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)multiplyWithLibOrgBouncycastleMathEcSimpleBigDecimal:(LibOrgBouncycastleMathEcSimpleBigDecimal *)b {
  LibOrgBouncycastleMathEcSimpleBigDecimal_checkScaleWithLibOrgBouncycastleMathEcSimpleBigDecimal_(self, b);
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) multiplyWithJavaMathBigInteger:((LibOrgBouncycastleMathEcSimpleBigDecimal *) nil_chk(b))->bigInt_], scale__ + scale__);
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)multiplyWithJavaMathBigInteger:(JavaMathBigInteger *)b {
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) multiplyWithJavaMathBigInteger:b], scale__);
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)divideWithLibOrgBouncycastleMathEcSimpleBigDecimal:(LibOrgBouncycastleMathEcSimpleBigDecimal *)b {
  LibOrgBouncycastleMathEcSimpleBigDecimal_checkScaleWithLibOrgBouncycastleMathEcSimpleBigDecimal_(self, b);
  JavaMathBigInteger *dividend = [((JavaMathBigInteger *) nil_chk(bigInt_)) shiftLeftWithInt:scale__];
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(dividend)) divideWithJavaMathBigInteger:((LibOrgBouncycastleMathEcSimpleBigDecimal *) nil_chk(b))->bigInt_], scale__);
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)divideWithJavaMathBigInteger:(JavaMathBigInteger *)b {
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) divideWithJavaMathBigInteger:b], scale__);
}

- (LibOrgBouncycastleMathEcSimpleBigDecimal *)shiftLeftWithInt:(jint)n {
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(bigInt_)) shiftLeftWithInt:n], scale__);
}

- (jint)compareToWithLibOrgBouncycastleMathEcSimpleBigDecimal:(LibOrgBouncycastleMathEcSimpleBigDecimal *)val {
  LibOrgBouncycastleMathEcSimpleBigDecimal_checkScaleWithLibOrgBouncycastleMathEcSimpleBigDecimal_(self, val);
  return [((JavaMathBigInteger *) nil_chk(bigInt_)) compareToWithId:((LibOrgBouncycastleMathEcSimpleBigDecimal *) nil_chk(val))->bigInt_];
}

- (jint)compareToWithJavaMathBigInteger:(JavaMathBigInteger *)val {
  return [((JavaMathBigInteger *) nil_chk(bigInt_)) compareToWithId:[((JavaMathBigInteger *) nil_chk(val)) shiftLeftWithInt:scale__]];
}

- (JavaMathBigInteger *)floor {
  return [((JavaMathBigInteger *) nil_chk(bigInt_)) shiftRightWithInt:scale__];
}

- (JavaMathBigInteger *)round {
  LibOrgBouncycastleMathEcSimpleBigDecimal *oneHalf = new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE), 1);
  return [((LibOrgBouncycastleMathEcSimpleBigDecimal *) nil_chk([self addWithLibOrgBouncycastleMathEcSimpleBigDecimal:[oneHalf adjustScaleWithInt:scale__]])) floor];
}

- (jint)intValue {
  return [((JavaMathBigInteger *) nil_chk([self floor])) intValue];
}

- (jlong)longValue {
  return [((JavaMathBigInteger *) nil_chk([self floor])) longLongValue];
}

- (jint)getScale {
  return scale__;
}

- (NSString *)description {
  if (scale__ == 0) {
    return [((JavaMathBigInteger *) nil_chk(bigInt_)) description];
  }
  JavaMathBigInteger *floorBigInt = [self floor];
  JavaMathBigInteger *fract = [((JavaMathBigInteger *) nil_chk(bigInt_)) subtractWithJavaMathBigInteger:[((JavaMathBigInteger *) nil_chk(floorBigInt)) shiftLeftWithInt:scale__]];
  if ([bigInt_ signum] == -1) {
    fract = [((JavaMathBigInteger *) nil_chk([((JavaMathBigInteger *) nil_chk(JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE))) shiftLeftWithInt:scale__])) subtractWithJavaMathBigInteger:fract];
  }
  if (([floorBigInt signum] == -1) && (!([((JavaMathBigInteger *) nil_chk(fract)) isEqual:JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ZERO)]))) {
    floorBigInt = [floorBigInt addWithJavaMathBigInteger:JreLoadStatic(LibOrgBouncycastleMathEcECConstants, ONE)];
  }
  NSString *leftOfPoint = [((JavaMathBigInteger *) nil_chk(floorBigInt)) description];
  IOSCharArray *fractCharArr = [IOSCharArray newArrayWithLength:scale__];
  NSString *fractStr = [((JavaMathBigInteger *) nil_chk(fract)) toStringWithInt:2];
  jint fractLen = [((NSString *) nil_chk(fractStr)) java_length];
  jint zeroes = scale__ - fractLen;
  for (jint i = 0; i < zeroes; i++) {
    *IOSCharArray_GetRef(fractCharArr, i) = '0';
  }
  for (jint j = 0; j < fractLen; j++) {
    *IOSCharArray_GetRef(fractCharArr, zeroes + j) = [fractStr charAtWithInt:j];
  }
  NSString *rightOfPoint = [NSString java_stringWithCharacters:fractCharArr];
  JavaLangStringBuffer *sb = new_JavaLangStringBuffer_initWithNSString_(leftOfPoint);
  (void) [sb appendWithNSString:@"."];
  (void) [sb appendWithNSString:rightOfPoint];
  return [sb description];
}

- (jboolean)isEqual:(id)o {
  if (self == o) {
    return true;
  }
  if (!([o isKindOfClass:[LibOrgBouncycastleMathEcSimpleBigDecimal class]])) {
    return false;
  }
  LibOrgBouncycastleMathEcSimpleBigDecimal *other = (LibOrgBouncycastleMathEcSimpleBigDecimal *) cast_chk(o, [LibOrgBouncycastleMathEcSimpleBigDecimal class]);
  return (([((JavaMathBigInteger *) nil_chk(bigInt_)) isEqual:((LibOrgBouncycastleMathEcSimpleBigDecimal *) nil_chk(other))->bigInt_]) && (scale__ == other->scale__));
}

- (NSUInteger)hash {
  return ((jint) [((JavaMathBigInteger *) nil_chk(bigInt_)) hash]) ^ scale__;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, 6, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, 8, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, 8, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, 9, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, 9, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, 10, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, 10, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcSimpleBigDecimal;", 0x1, 11, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 12, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 12, 7, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "J", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, 13, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 14, 15, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 16, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithJavaMathBigInteger:withInt:);
  methods[1].selector = @selector(initWithJavaMathBigInteger:withInt:);
  methods[2].selector = @selector(checkScaleWithLibOrgBouncycastleMathEcSimpleBigDecimal:);
  methods[3].selector = @selector(adjustScaleWithInt:);
  methods[4].selector = @selector(addWithLibOrgBouncycastleMathEcSimpleBigDecimal:);
  methods[5].selector = @selector(addWithJavaMathBigInteger:);
  methods[6].selector = @selector(negate);
  methods[7].selector = @selector(subtractWithLibOrgBouncycastleMathEcSimpleBigDecimal:);
  methods[8].selector = @selector(subtractWithJavaMathBigInteger:);
  methods[9].selector = @selector(multiplyWithLibOrgBouncycastleMathEcSimpleBigDecimal:);
  methods[10].selector = @selector(multiplyWithJavaMathBigInteger:);
  methods[11].selector = @selector(divideWithLibOrgBouncycastleMathEcSimpleBigDecimal:);
  methods[12].selector = @selector(divideWithJavaMathBigInteger:);
  methods[13].selector = @selector(shiftLeftWithInt:);
  methods[14].selector = @selector(compareToWithLibOrgBouncycastleMathEcSimpleBigDecimal:);
  methods[15].selector = @selector(compareToWithJavaMathBigInteger:);
  methods[16].selector = @selector(floor);
  methods[17].selector = @selector(round);
  methods[18].selector = @selector(intValue);
  methods[19].selector = @selector(longValue);
  methods[20].selector = @selector(getScale);
  methods[21].selector = @selector(description);
  methods[22].selector = @selector(isEqual:);
  methods[23].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "serialVersionUID", "J", .constantValue.asLong = LibOrgBouncycastleMathEcSimpleBigDecimal_serialVersionUID, 0x1a, -1, -1, -1, -1 },
    { "bigInt_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "scale__", "I", .constantValue.asLong = 0, 0x12, 17, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LJavaMathBigInteger;I", "checkScale", "LLibOrgBouncycastleMathEcSimpleBigDecimal;", "adjustScale", "I", "add", "LJavaMathBigInteger;", "subtract", "multiply", "divide", "shiftLeft", "compareTo", "toString", "equals", "LNSObject;", "hashCode", "scale" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcSimpleBigDecimal = { "SimpleBigDecimal", "lib.org.bouncycastle.math.ec", ptrTable, methods, fields, 7, 0x0, 24, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcSimpleBigDecimal;
}

@end

LibOrgBouncycastleMathEcSimpleBigDecimal *LibOrgBouncycastleMathEcSimpleBigDecimal_getInstanceWithJavaMathBigInteger_withInt_(JavaMathBigInteger *value, jint scale_) {
  LibOrgBouncycastleMathEcSimpleBigDecimal_initialize();
  return new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_([((JavaMathBigInteger *) nil_chk(value)) shiftLeftWithInt:scale_], scale_);
}

void LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(LibOrgBouncycastleMathEcSimpleBigDecimal *self, JavaMathBigInteger *bigInt, jint scale_) {
  NSObject_init(self);
  if (scale_ < 0) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"scale may not be negative");
  }
  self->bigInt_ = bigInt;
  self->scale__ = scale_;
}

LibOrgBouncycastleMathEcSimpleBigDecimal *new_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(JavaMathBigInteger *bigInt, jint scale_) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcSimpleBigDecimal, initWithJavaMathBigInteger_withInt_, bigInt, scale_)
}

LibOrgBouncycastleMathEcSimpleBigDecimal *create_LibOrgBouncycastleMathEcSimpleBigDecimal_initWithJavaMathBigInteger_withInt_(JavaMathBigInteger *bigInt, jint scale_) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcSimpleBigDecimal, initWithJavaMathBigInteger_withInt_, bigInt, scale_)
}

void LibOrgBouncycastleMathEcSimpleBigDecimal_checkScaleWithLibOrgBouncycastleMathEcSimpleBigDecimal_(LibOrgBouncycastleMathEcSimpleBigDecimal *self, LibOrgBouncycastleMathEcSimpleBigDecimal *b) {
  if (self->scale__ != ((LibOrgBouncycastleMathEcSimpleBigDecimal *) nil_chk(b))->scale__) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Only SimpleBigDecimal of same scale allowed in arithmetic operations");
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcSimpleBigDecimal)
