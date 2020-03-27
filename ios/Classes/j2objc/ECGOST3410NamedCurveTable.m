//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/ECGOST3410NamedCurveTable.java
//

#include "ASN1ObjectIdentifier.h"
#include "ECCurve.h"
#include "ECDomainParameters.h"
#include "ECGOST3410NamedCurveTable.h"
#include "ECGOST3410NamedCurves.h"
#include "ECNamedCurveParameterSpec.h"
#include "ECPoint.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"
#include "java/util/Enumeration.h"

@implementation LibOrgBouncycastleJceECGOST3410NamedCurveTable

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJceECGOST3410NamedCurveTable_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (LibOrgBouncycastleJceSpecECNamedCurveParameterSpec *)getParameterSpecWithNSString:(NSString *)name {
  return LibOrgBouncycastleJceECGOST3410NamedCurveTable_getParameterSpecWithNSString_(name);
}

+ (id<JavaUtilEnumeration>)getNames {
  return LibOrgBouncycastleJceECGOST3410NamedCurveTable_getNames();
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleJceSpecECNamedCurveParameterSpec;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilEnumeration;", 0x9, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getParameterSpecWithNSString:);
  methods[2].selector = @selector(getNames);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "getParameterSpec", "LNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceECGOST3410NamedCurveTable = { "ECGOST3410NamedCurveTable", "lib.org.bouncycastle.jce", ptrTable, methods, NULL, 7, 0x1, 3, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceECGOST3410NamedCurveTable;
}

@end

void LibOrgBouncycastleJceECGOST3410NamedCurveTable_init(LibOrgBouncycastleJceECGOST3410NamedCurveTable *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJceECGOST3410NamedCurveTable *new_LibOrgBouncycastleJceECGOST3410NamedCurveTable_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceECGOST3410NamedCurveTable, init)
}

LibOrgBouncycastleJceECGOST3410NamedCurveTable *create_LibOrgBouncycastleJceECGOST3410NamedCurveTable_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceECGOST3410NamedCurveTable, init)
}

LibOrgBouncycastleJceSpecECNamedCurveParameterSpec *LibOrgBouncycastleJceECGOST3410NamedCurveTable_getParameterSpecWithNSString_(NSString *name) {
  LibOrgBouncycastleJceECGOST3410NamedCurveTable_initialize();
  LibOrgBouncycastleCryptoParamsECDomainParameters *ecP = LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getByNameWithNSString_(name);
  if (ecP == nil) {
    @try {
      ecP = LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getByOIDWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(new_LibOrgBouncycastleAsn1ASN1ObjectIdentifier_initWithNSString_(name));
    }
    @catch (JavaLangIllegalArgumentException *e) {
      return nil;
    }
  }
  if (ecP == nil) {
    return nil;
  }
  return new_LibOrgBouncycastleJceSpecECNamedCurveParameterSpec_initWithNSString_withLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(name, [ecP getCurve], [ecP getG], [ecP getN], [ecP getH], [ecP getSeed]);
}

id<JavaUtilEnumeration> LibOrgBouncycastleJceECGOST3410NamedCurveTable_getNames() {
  LibOrgBouncycastleJceECGOST3410NamedCurveTable_initialize();
  return LibOrgBouncycastleAsn1CryptoproECGOST3410NamedCurves_getNames();
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceECGOST3410NamedCurveTable)
