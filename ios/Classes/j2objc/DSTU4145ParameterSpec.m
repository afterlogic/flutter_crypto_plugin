//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/spec/DSTU4145ParameterSpec.java
//

#include "Arrays.h"
#include "DSTU4145ParameterSpec.h"
#include "DSTU4145Params.h"
#include "EC5Util.h"
#include "ECDomainParameters.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "java/security/spec/ECParameterSpec.h"
#include "java/security/spec/ECPoint.h"
#include "java/security/spec/EllipticCurve.h"

@interface LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec () {
 @public
  IOSByteArray *dke_;
  LibOrgBouncycastleCryptoParamsECDomainParameters *parameters_;
}

- (instancetype)initWithLibOrgBouncycastleCryptoParamsECDomainParameters:(LibOrgBouncycastleCryptoParamsECDomainParameters *)parameters
                                     withJavaSecuritySpecECParameterSpec:(JavaSecuritySpecECParameterSpec *)ecParameterSpec
                                                           withByteArray:(IOSByteArray *)dke;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec, dke_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec, parameters_, LibOrgBouncycastleCryptoParamsECDomainParameters *)

__attribute__((unused)) static void LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySpecECParameterSpec_withByteArray_(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *self, LibOrgBouncycastleCryptoParamsECDomainParameters *parameters, JavaSecuritySpecECParameterSpec *ecParameterSpec, IOSByteArray *dke);

__attribute__((unused)) static LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *new_LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySpecECParameterSpec_withByteArray_(LibOrgBouncycastleCryptoParamsECDomainParameters *parameters, JavaSecuritySpecECParameterSpec *ecParameterSpec, IOSByteArray *dke) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *create_LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySpecECParameterSpec_withByteArray_(LibOrgBouncycastleCryptoParamsECDomainParameters *parameters, JavaSecuritySpecECParameterSpec *ecParameterSpec, IOSByteArray *dke);

@implementation LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec

- (instancetype)initWithLibOrgBouncycastleCryptoParamsECDomainParameters:(LibOrgBouncycastleCryptoParamsECDomainParameters *)parameters {
  LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_(self, parameters);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleCryptoParamsECDomainParameters:(LibOrgBouncycastleCryptoParamsECDomainParameters *)parameters
                                     withJavaSecuritySpecECParameterSpec:(JavaSecuritySpecECParameterSpec *)ecParameterSpec
                                                           withByteArray:(IOSByteArray *)dke {
  LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySpecECParameterSpec_withByteArray_(self, parameters, ecParameterSpec, dke);
  return self;
}

- (IOSByteArray *)getDKE {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(dke_);
}

- (jboolean)isEqual:(id)o {
  if ([o isKindOfClass:[LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec class]]) {
    LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *other = (LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *) o;
    return [((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(self->parameters_)) isEqual:((LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *) nil_chk(other))->parameters_];
  }
  return false;
}

- (NSUInteger)hash {
  return ((jint) [((LibOrgBouncycastleCryptoParamsECDomainParameters *) nil_chk(self->parameters_)) hash]);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x2, -1, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 4, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleCryptoParamsECDomainParameters:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleCryptoParamsECDomainParameters:withJavaSecuritySpecECParameterSpec:withByteArray:);
  methods[2].selector = @selector(getDKE);
  methods[3].selector = @selector(isEqual:);
  methods[4].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "dke_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "parameters_", "LLibOrgBouncycastleCryptoParamsECDomainParameters;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleCryptoParamsECDomainParameters;", "LLibOrgBouncycastleCryptoParamsECDomainParameters;LJavaSecuritySpecECParameterSpec;[B", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec = { "DSTU4145ParameterSpec", "lib.org.bouncycastle.jcajce.spec", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec;
}

@end

void LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *self, LibOrgBouncycastleCryptoParamsECDomainParameters *parameters) {
  LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySpecECParameterSpec_withByteArray_(self, parameters, LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_convertToSpecWithLibOrgBouncycastleCryptoParamsECDomainParameters_(parameters), LibOrgBouncycastleAsn1UaDSTU4145Params_getDefaultDKE());
}

LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *new_LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_(LibOrgBouncycastleCryptoParamsECDomainParameters *parameters) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec, initWithLibOrgBouncycastleCryptoParamsECDomainParameters_, parameters)
}

LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *create_LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_(LibOrgBouncycastleCryptoParamsECDomainParameters *parameters) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec, initWithLibOrgBouncycastleCryptoParamsECDomainParameters_, parameters)
}

void LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySpecECParameterSpec_withByteArray_(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *self, LibOrgBouncycastleCryptoParamsECDomainParameters *parameters, JavaSecuritySpecECParameterSpec *ecParameterSpec, IOSByteArray *dke) {
  JavaSecuritySpecECParameterSpec_initWithJavaSecuritySpecEllipticCurve_withJavaSecuritySpecECPoint_withJavaMathBigInteger_withInt_(self, [((JavaSecuritySpecECParameterSpec *) nil_chk(ecParameterSpec)) getCurve], [ecParameterSpec getGenerator], [ecParameterSpec getOrder], [ecParameterSpec getCofactor]);
  self->parameters_ = parameters;
  self->dke_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(dke);
}

LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *new_LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySpecECParameterSpec_withByteArray_(LibOrgBouncycastleCryptoParamsECDomainParameters *parameters, JavaSecuritySpecECParameterSpec *ecParameterSpec, IOSByteArray *dke) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec, initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySpecECParameterSpec_withByteArray_, parameters, ecParameterSpec, dke)
}

LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec *create_LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec_initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySpecECParameterSpec_withByteArray_(LibOrgBouncycastleCryptoParamsECDomainParameters *parameters, JavaSecuritySpecECParameterSpec *ecParameterSpec, IOSByteArray *dke) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec, initWithLibOrgBouncycastleCryptoParamsECDomainParameters_withJavaSecuritySpecECParameterSpec_withByteArray_, parameters, ecParameterSpec, dke)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceSpecDSTU4145ParameterSpec)