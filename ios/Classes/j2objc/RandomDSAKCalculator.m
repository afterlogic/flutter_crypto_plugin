//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/RandomDSAKCalculator.java
//

#include "BigIntegers.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "RandomDSAKCalculator.h"
#include "java/lang/IllegalStateException.h"
#include "java/math/BigInteger.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastleCryptoSignersRandomDSAKCalculator () {
 @public
  JavaMathBigInteger *q_;
  JavaSecuritySecureRandom *random_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersRandomDSAKCalculator, q_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersRandomDSAKCalculator, random_, JavaSecuritySecureRandom *)

inline JavaMathBigInteger *LibOrgBouncycastleCryptoSignersRandomDSAKCalculator_get_ZERO(void);
static JavaMathBigInteger *LibOrgBouncycastleCryptoSignersRandomDSAKCalculator_ZERO;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleCryptoSignersRandomDSAKCalculator, ZERO, JavaMathBigInteger *)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleCryptoSignersRandomDSAKCalculator)

@implementation LibOrgBouncycastleCryptoSignersRandomDSAKCalculator

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoSignersRandomDSAKCalculator_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)isDeterministic {
  return false;
}

- (void)init__WithJavaMathBigInteger:(JavaMathBigInteger *)n
        withJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
  self->q_ = n;
  self->random_ = random;
}

- (void)init__WithJavaMathBigInteger:(JavaMathBigInteger *)n
              withJavaMathBigInteger:(JavaMathBigInteger *)d
                       withByteArray:(IOSByteArray *)message {
  @throw new_JavaLangIllegalStateException_initWithNSString_(@"Operation not supported");
}

- (JavaMathBigInteger *)nextK {
  jint qBitLength = [((JavaMathBigInteger *) nil_chk(q_)) bitLength];
  JavaMathBigInteger *k;
  do {
    k = LibOrgBouncycastleUtilBigIntegers_createRandomBigIntegerWithInt_withJavaSecuritySecureRandom_(qBitLength, random_);
  }
  while ([((JavaMathBigInteger *) nil_chk(k)) isEqual:LibOrgBouncycastleCryptoSignersRandomDSAKCalculator_ZERO] || [k compareToWithId:q_] >= 0);
  return k;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 2, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isDeterministic);
  methods[2].selector = @selector(init__WithJavaMathBigInteger:withJavaSecuritySecureRandom:);
  methods[3].selector = @selector(init__WithJavaMathBigInteger:withJavaMathBigInteger:withByteArray:);
  methods[4].selector = @selector(nextK);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ZERO", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x1a, -1, 3, -1, -1 },
    { "q_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "init", "LJavaMathBigInteger;LJavaSecuritySecureRandom;", "LJavaMathBigInteger;LJavaMathBigInteger;[B", &LibOrgBouncycastleCryptoSignersRandomDSAKCalculator_ZERO };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSignersRandomDSAKCalculator = { "RandomDSAKCalculator", "lib.org.bouncycastle.crypto.signers", ptrTable, methods, fields, 7, 0x1, 5, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSignersRandomDSAKCalculator;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleCryptoSignersRandomDSAKCalculator class]) {
    LibOrgBouncycastleCryptoSignersRandomDSAKCalculator_ZERO = JavaMathBigInteger_valueOfWithLong_(0);
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleCryptoSignersRandomDSAKCalculator)
  }
}

@end

void LibOrgBouncycastleCryptoSignersRandomDSAKCalculator_init(LibOrgBouncycastleCryptoSignersRandomDSAKCalculator *self) {
  NSObject_init(self);
}

LibOrgBouncycastleCryptoSignersRandomDSAKCalculator *new_LibOrgBouncycastleCryptoSignersRandomDSAKCalculator_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersRandomDSAKCalculator, init)
}

LibOrgBouncycastleCryptoSignersRandomDSAKCalculator *create_LibOrgBouncycastleCryptoSignersRandomDSAKCalculator_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersRandomDSAKCalculator, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSignersRandomDSAKCalculator)
