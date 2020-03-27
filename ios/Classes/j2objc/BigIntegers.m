//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/util/BigIntegers.java
//

#include "BigIntegers.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/System.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleUtilBigIntegers ()

+ (IOSByteArray *)createRandomWithInt:(jint)bitLength
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random;

@end

inline JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_get_TWO(void);
static JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_TWO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleUtilBigIntegers, TWO, JavaMathBigInteger *)

inline JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_get_THREE(void);
static JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_THREE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleUtilBigIntegers, THREE, JavaMathBigInteger *)

inline jint LibOrgBouncycastleUtilBigIntegers_get_MAX_ITERATIONS(void);
#define LibOrgBouncycastleUtilBigIntegers_MAX_ITERATIONS 1000
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleUtilBigIntegers, MAX_ITERATIONS, jint)

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastleUtilBigIntegers_createRandomWithInt_withJavaSecuritySecureRandom_(jint bitLength, JavaSecuritySecureRandom *random);

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleUtilBigIntegers)

JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_ZERO;
JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_ONE;

@implementation LibOrgBouncycastleUtilBigIntegers

+ (JavaMathBigInteger *)ZERO {
  return LibOrgBouncycastleUtilBigIntegers_ZERO;
}

+ (JavaMathBigInteger *)ONE {
  return LibOrgBouncycastleUtilBigIntegers_ONE;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleUtilBigIntegers_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (IOSByteArray *)asUnsignedByteArrayWithJavaMathBigInteger:(JavaMathBigInteger *)value {
  return LibOrgBouncycastleUtilBigIntegers_asUnsignedByteArrayWithJavaMathBigInteger_(value);
}

+ (IOSByteArray *)asUnsignedByteArrayWithInt:(jint)length
                      withJavaMathBigInteger:(JavaMathBigInteger *)value {
  return LibOrgBouncycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_(length, value);
}

+ (JavaMathBigInteger *)createRandomInRangeWithJavaMathBigInteger:(JavaMathBigInteger *)min
                                           withJavaMathBigInteger:(JavaMathBigInteger *)max
                                     withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(min, max, random);
}

+ (JavaMathBigInteger *)fromUnsignedByteArrayWithByteArray:(IOSByteArray *)buf {
  return LibOrgBouncycastleUtilBigIntegers_fromUnsignedByteArrayWithByteArray_(buf);
}

+ (JavaMathBigInteger *)fromUnsignedByteArrayWithByteArray:(IOSByteArray *)buf
                                                   withInt:(jint)off
                                                   withInt:(jint)length {
  return LibOrgBouncycastleUtilBigIntegers_fromUnsignedByteArrayWithByteArray_withInt_withInt_(buf, off, length);
}

+ (jint)getUnsignedByteLengthWithJavaMathBigInteger:(JavaMathBigInteger *)n {
  return LibOrgBouncycastleUtilBigIntegers_getUnsignedByteLengthWithJavaMathBigInteger_(n);
}

+ (JavaMathBigInteger *)createRandomBigIntegerWithInt:(jint)bitLength
                         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleUtilBigIntegers_createRandomBigIntegerWithInt_withJavaSecuritySecureRandom_(bitLength, random);
}

+ (JavaMathBigInteger *)createRandomPrimeWithInt:(jint)bitLength
                                         withInt:(jint)certainty
                    withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleUtilBigIntegers_createRandomPrimeWithInt_withInt_withJavaSecuritySecureRandom_(bitLength, certainty, random);
}

+ (IOSByteArray *)createRandomWithInt:(jint)bitLength
         withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  return LibOrgBouncycastleUtilBigIntegers_createRandomWithInt_withJavaSecuritySecureRandom_(bitLength, random);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 5, 6, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 5, 7, -1, -1, -1, -1 },
    { NULL, "I", 0x9, 8, 1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 9, 10, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x9, 11, 12, -1, -1, -1, -1 },
    { NULL, "[B", 0xa, 13, 10, 14, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(asUnsignedByteArrayWithJavaMathBigInteger:);
  methods[2].selector = @selector(asUnsignedByteArrayWithInt:withJavaMathBigInteger:);
  methods[3].selector = @selector(createRandomInRangeWithJavaMathBigInteger:withJavaMathBigInteger:withJavaSecuritySecureRandom:);
  methods[4].selector = @selector(fromUnsignedByteArrayWithByteArray:);
  methods[5].selector = @selector(fromUnsignedByteArrayWithByteArray:withInt:withInt:);
  methods[6].selector = @selector(getUnsignedByteLengthWithJavaMathBigInteger:);
  methods[7].selector = @selector(createRandomBigIntegerWithInt:withJavaSecuritySecureRandom:);
  methods[8].selector = @selector(createRandomPrimeWithInt:withInt:withJavaSecuritySecureRandom:);
  methods[9].selector = @selector(createRandomWithInt:withJavaSecuritySecureRandom:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ZERO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x19, -1, 15, -1, -1 },
    { "ONE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x19, -1, 16, -1, -1 },
    { "TWO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 17, -1, -1 },
    { "THREE", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 18, -1, -1 },
    { "MAX_ITERATIONS", "I", .constantValue.asInt = LibOrgBouncycastleUtilBigIntegers_MAX_ITERATIONS, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "asUnsignedByteArray", "LJavaMathBigInteger;", "ILJavaMathBigInteger;", "createRandomInRange", "LJavaMathBigInteger;LJavaMathBigInteger;LJavaSecuritySecureRandom;", "fromUnsignedByteArray", "[B", "[BII", "getUnsignedByteLength", "createRandomBigInteger", "ILJavaSecuritySecureRandom;", "createRandomPrime", "IILJavaSecuritySecureRandom;", "createRandom", "LJavaLangIllegalArgumentException;", &LibOrgBouncycastleUtilBigIntegers_ZERO, &LibOrgBouncycastleUtilBigIntegers_ONE, &LibOrgBouncycastleUtilBigIntegers_TWO, &LibOrgBouncycastleUtilBigIntegers_THREE };
  static const J2ObjcClassInfo _LibOrgBouncycastleUtilBigIntegers = { "BigIntegers", "lib.org.bouncycastle.util", ptrTable, methods, fields, 7, 0x11, 10, 5, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleUtilBigIntegers;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleUtilBigIntegers class]) {
    LibOrgBouncycastleUtilBigIntegers_ZERO = JavaMathBigInteger_valueOfWithLong_(0);
    LibOrgBouncycastleUtilBigIntegers_ONE = JavaMathBigInteger_valueOfWithLong_(1);
    LibOrgBouncycastleUtilBigIntegers_TWO = JavaMathBigInteger_valueOfWithLong_(2);
    LibOrgBouncycastleUtilBigIntegers_THREE = JavaMathBigInteger_valueOfWithLong_(3);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleUtilBigIntegers)
  }
}

@end

void LibOrgBouncycastleUtilBigIntegers_init(LibOrgBouncycastleUtilBigIntegers *self) {
  NSObject_init(self);
}

LibOrgBouncycastleUtilBigIntegers *new_LibOrgBouncycastleUtilBigIntegers_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleUtilBigIntegers, init)
}

LibOrgBouncycastleUtilBigIntegers *create_LibOrgBouncycastleUtilBigIntegers_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleUtilBigIntegers, init)
}

IOSByteArray *LibOrgBouncycastleUtilBigIntegers_asUnsignedByteArrayWithJavaMathBigInteger_(JavaMathBigInteger *value) {
  LibOrgBouncycastleUtilBigIntegers_initialize();
  IOSByteArray *bytes = [((JavaMathBigInteger *) nil_chk(value)) toByteArray];
  if (IOSByteArray_Get(nil_chk(bytes), 0) == 0) {
    IOSByteArray *tmp = [IOSByteArray newArrayWithLength:bytes->size_ - 1];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(bytes, 1, tmp, 0, tmp->size_);
    return tmp;
  }
  return bytes;
}

IOSByteArray *LibOrgBouncycastleUtilBigIntegers_asUnsignedByteArrayWithInt_withJavaMathBigInteger_(jint length, JavaMathBigInteger *value) {
  LibOrgBouncycastleUtilBigIntegers_initialize();
  IOSByteArray *bytes = [((JavaMathBigInteger *) nil_chk(value)) toByteArray];
  if (((IOSByteArray *) nil_chk(bytes))->size_ == length) {
    return bytes;
  }
  jint start = IOSByteArray_Get(bytes, 0) == 0 ? 1 : 0;
  jint count = bytes->size_ - start;
  if (count > length) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"standard length exceeded for value");
  }
  IOSByteArray *tmp = [IOSByteArray newArrayWithLength:length];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(bytes, start, tmp, tmp->size_ - count, count);
  return tmp;
}

JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(JavaMathBigInteger *min, JavaMathBigInteger *max, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleUtilBigIntegers_initialize();
  jint cmp = [((JavaMathBigInteger *) nil_chk(min)) compareToWithId:max];
  if (cmp >= 0) {
    if (cmp > 0) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"'min' may not be greater than 'max'");
    }
    return min;
  }
  if ([min bitLength] > [((JavaMathBigInteger *) nil_chk(max)) bitLength] / 2) {
    return [((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleUtilBigIntegers_createRandomInRangeWithJavaMathBigInteger_withJavaMathBigInteger_withJavaSecuritySecureRandom_(LibOrgBouncycastleUtilBigIntegers_ZERO, [max subtractWithJavaMathBigInteger:min], random))) addWithJavaMathBigInteger:min];
  }
  for (jint i = 0; i < LibOrgBouncycastleUtilBigIntegers_MAX_ITERATIONS; ++i) {
    JavaMathBigInteger *x = LibOrgBouncycastleUtilBigIntegers_createRandomBigIntegerWithInt_withJavaSecuritySecureRandom_([max bitLength], random);
    if ([((JavaMathBigInteger *) nil_chk(x)) compareToWithId:min] >= 0 && [x compareToWithId:max] <= 0) {
      return x;
    }
  }
  return [((JavaMathBigInteger *) nil_chk(LibOrgBouncycastleUtilBigIntegers_createRandomBigIntegerWithInt_withJavaSecuritySecureRandom_([((JavaMathBigInteger *) nil_chk([max subtractWithJavaMathBigInteger:min])) bitLength] - 1, random))) addWithJavaMathBigInteger:min];
}

JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_fromUnsignedByteArrayWithByteArray_(IOSByteArray *buf) {
  LibOrgBouncycastleUtilBigIntegers_initialize();
  return new_JavaMathBigInteger_initWithInt_withByteArray_(1, buf);
}

JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_fromUnsignedByteArrayWithByteArray_withInt_withInt_(IOSByteArray *buf, jint off, jint length) {
  LibOrgBouncycastleUtilBigIntegers_initialize();
  IOSByteArray *mag = buf;
  if (off != 0 || length != ((IOSByteArray *) nil_chk(buf))->size_) {
    mag = [IOSByteArray newArrayWithLength:length];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(buf, off, mag, 0, length);
  }
  return new_JavaMathBigInteger_initWithInt_withByteArray_(1, mag);
}

jint LibOrgBouncycastleUtilBigIntegers_getUnsignedByteLengthWithJavaMathBigInteger_(JavaMathBigInteger *n) {
  LibOrgBouncycastleUtilBigIntegers_initialize();
  return ([((JavaMathBigInteger *) nil_chk(n)) bitLength] + 7) / 8;
}

JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_createRandomBigIntegerWithInt_withJavaSecuritySecureRandom_(jint bitLength, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleUtilBigIntegers_initialize();
  return new_JavaMathBigInteger_initWithInt_withByteArray_(1, LibOrgBouncycastleUtilBigIntegers_createRandomWithInt_withJavaSecuritySecureRandom_(bitLength, random));
}

JavaMathBigInteger *LibOrgBouncycastleUtilBigIntegers_createRandomPrimeWithInt_withInt_withJavaSecuritySecureRandom_(jint bitLength, jint certainty, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleUtilBigIntegers_initialize();
  if (bitLength < 2) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"bitLength < 2");
  }
  JavaMathBigInteger *rv;
  if (bitLength == 2) {
    return ([((JavaSecuritySecureRandom *) nil_chk(random)) nextInt] < 0) ? LibOrgBouncycastleUtilBigIntegers_TWO : LibOrgBouncycastleUtilBigIntegers_THREE;
  }
  do {
    IOSByteArray *base = LibOrgBouncycastleUtilBigIntegers_createRandomWithInt_withJavaSecuritySecureRandom_(bitLength, random);
    jint xBits = 8 * ((IOSByteArray *) nil_chk(base))->size_ - bitLength;
    jbyte lead = (jbyte) (JreLShift32(1, (7 - xBits)));
    *IOSByteArray_GetRef(base, 0) |= lead;
    *IOSByteArray_GetRef(base, base->size_ - 1) |= (jint) 0x01;
    rv = new_JavaMathBigInteger_initWithInt_withByteArray_(1, base);
  }
  while (![rv isProbablePrimeWithInt:certainty]);
  return rv;
}

IOSByteArray *LibOrgBouncycastleUtilBigIntegers_createRandomWithInt_withJavaSecuritySecureRandom_(jint bitLength, JavaSecuritySecureRandom *random) {
  LibOrgBouncycastleUtilBigIntegers_initialize();
  if (bitLength < 1) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"bitLength must be at least 1");
  }
  jint nBytes = (bitLength + 7) / 8;
  IOSByteArray *rv = [IOSByteArray newArrayWithLength:nBytes];
  [((JavaSecuritySecureRandom *) nil_chk(random)) nextBytesWithByteArray:rv];
  jint xBits = 8 * nBytes - bitLength;
  *IOSByteArray_GetRef(rv, 0) &= (jbyte) (JreURShift32(255, xBits));
  return rv;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleUtilBigIntegers)
