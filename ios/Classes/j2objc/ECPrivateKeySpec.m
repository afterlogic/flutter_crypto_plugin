//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/spec/ECPrivateKeySpec.java
//

#include "ECKeySpec.h"
#include "ECParameterSpec.h"
#include "ECPrivateKeySpec.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleJceSpecECPrivateKeySpec () {
 @public
  JavaMathBigInteger *d_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJceSpecECPrivateKeySpec, d_, JavaMathBigInteger *)

@implementation LibOrgBouncycastleJceSpecECPrivateKeySpec

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)d
withLibOrgBouncycastleJceSpecECParameterSpec:(LibOrgBouncycastleJceSpecECParameterSpec *)spec {
  LibOrgBouncycastleJceSpecECPrivateKeySpec_initWithJavaMathBigInteger_withLibOrgBouncycastleJceSpecECParameterSpec_(self, d, spec);
  return self;
}

- (JavaMathBigInteger *)getD {
  return d_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withLibOrgBouncycastleJceSpecECParameterSpec:);
  methods[1].selector = @selector(getD);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "d_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LLibOrgBouncycastleJceSpecECParameterSpec;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceSpecECPrivateKeySpec = { "ECPrivateKeySpec", "lib.org.bouncycastle.jce.spec", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceSpecECPrivateKeySpec;
}

@end

void LibOrgBouncycastleJceSpecECPrivateKeySpec_initWithJavaMathBigInteger_withLibOrgBouncycastleJceSpecECParameterSpec_(LibOrgBouncycastleJceSpecECPrivateKeySpec *self, JavaMathBigInteger *d, LibOrgBouncycastleJceSpecECParameterSpec *spec) {
  LibOrgBouncycastleJceSpecECKeySpec_initWithLibOrgBouncycastleJceSpecECParameterSpec_(self, spec);
  self->d_ = d;
}

LibOrgBouncycastleJceSpecECPrivateKeySpec *new_LibOrgBouncycastleJceSpecECPrivateKeySpec_initWithJavaMathBigInteger_withLibOrgBouncycastleJceSpecECParameterSpec_(JavaMathBigInteger *d, LibOrgBouncycastleJceSpecECParameterSpec *spec) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceSpecECPrivateKeySpec, initWithJavaMathBigInteger_withLibOrgBouncycastleJceSpecECParameterSpec_, d, spec)
}

LibOrgBouncycastleJceSpecECPrivateKeySpec *create_LibOrgBouncycastleJceSpecECPrivateKeySpec_initWithJavaMathBigInteger_withLibOrgBouncycastleJceSpecECParameterSpec_(JavaMathBigInteger *d, LibOrgBouncycastleJceSpecECParameterSpec *spec) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceSpecECPrivateKeySpec, initWithJavaMathBigInteger_withLibOrgBouncycastleJceSpecECParameterSpec_, d, spec)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceSpecECPrivateKeySpec)
