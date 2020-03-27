//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/generation/type/ElGamal_GENERAL.java
//

#include "ElGamalLength.h"
#include "ElGamalParameterSpec.h"
#include "ElGamal_GENERAL.h"
#include "J2ObjC_source.h"
#include "PublicKeyAlgorithm.h"
#include "java/math/BigInteger.h"
#include "java/security/spec/AlgorithmParameterSpec.h"

@interface LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL () {
 @public
  LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *length_;
}

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL, length_, LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)

@implementation LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL

- (instancetype)initWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength:(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)length {
  LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL_initWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_(self, length);
  return self;
}

+ (LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL *)withLengthWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength:(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)length {
  return LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL_withLengthWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_(length);
}

- (NSString *)getName {
  return @"ElGamal";
}

- (LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm *)getAlgorithm {
  return JreLoadEnum(LibComAfterlogicPgpAlgorithmPublicKeyAlgorithm, ELGAMAL_GENERAL);
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)getAlgorithmSpec {
  return new_LibOrgBouncycastleJceSpecElGamalParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_([((LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *) nil_chk(length_)) getP], [length_ getG]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL;", 0x9, 1, 0, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpAlgorithmPublicKeyAlgorithm;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength:);
  methods[1].selector = @selector(withLengthWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength:);
  methods[2].selector = @selector(getName);
  methods[3].selector = @selector(getAlgorithm);
  methods[4].selector = @selector(getAlgorithmSpec);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "length_", "LLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;", "withLength" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL = { "ElGamal_GENERAL", "lib.com.afterlogic.pgp.key.generation.type", ptrTable, methods, fields, 7, 0x1, 5, 1, -1, -1, -1, -1, -1 };
  return &_LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL;
}

@end

void LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL_initWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_(LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL *self, LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *length) {
  NSObject_init(self);
  self->length_ = length;
}

LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL *new_LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL_initWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *length) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL, initWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_, length)
}

LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL *create_LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL_initWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *length) {
  J2OBJC_CREATE_IMPL(LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL, initWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_, length)
}

LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL *LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL_withLengthWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *length) {
  LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL_initialize();
  return new_LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL_initWithLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_(length);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyGenerationTypeElGamal_GENERAL)
