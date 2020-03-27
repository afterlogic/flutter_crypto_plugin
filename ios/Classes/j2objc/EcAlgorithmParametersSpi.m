//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/ec/EcAlgorithmParametersSpi.java
//

#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "BouncyCastleProvider.h"
#include "DERNull.h"
#include "EC5Util.h"
#include "ECCurve.h"
#include "ECNamedCurveSpec.h"
#include "ECNamedCurveTable.h"
#include "ECParameterSpec.h"
#include "ECPoint.h"
#include "ECUtils.h"
#include "EcAlgorithmParametersSpi.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcajceUtilECUtil.h"
#include "ProviderConfiguration.h"
#include "X962Parameters.h"
#include "X9ECParameters.h"
#include "java/io/IOException.h"
#include "java/math/BigInteger.h"
#include "java/security/AlgorithmParametersSpi.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "java/security/spec/ECGenParameterSpec.h"
#include "java/security/spec/ECParameterSpec.h"
#include "java/security/spec/ECPoint.h"
#include "java/security/spec/EllipticCurve.h"
#include "java/security/spec/InvalidParameterSpecException.h"

@interface LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi () {
 @public
  JavaSecuritySpecECParameterSpec *ecParameterSpec_;
  NSString *curveName_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi, ecParameterSpec_, JavaSecuritySpecECParameterSpec *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi, curveName_, NSString *)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)isASN1FormatStringWithNSString:(NSString *)format {
  return format == nil || [format isEqual:@"ASN.1"];
}

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)algorithmParameterSpec {
  if ([algorithmParameterSpec isKindOfClass:[JavaSecuritySpecECGenParameterSpec class]]) {
    JavaSecuritySpecECGenParameterSpec *ecGenParameterSpec = (JavaSecuritySpecECGenParameterSpec *) algorithmParameterSpec;
    LibOrgBouncycastleAsn1X9X9ECParameters *params = LibOrgBouncycastleJcajceProviderAsymmetricEcECUtils_getDomainParametersFromGenSpecWithJavaSecuritySpecECGenParameterSpec_(ecGenParameterSpec);
    if (params == nil) {
      @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(JreStrcat("$$", @"EC curve name not recognized: ", [((JavaSecuritySpecECGenParameterSpec *) nil_chk(ecGenParameterSpec)) getName]));
    }
    curveName_ = [((JavaSecuritySpecECGenParameterSpec *) nil_chk(ecGenParameterSpec)) getName];
    JavaSecuritySpecECParameterSpec *baseSpec = LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_convertToSpecWithLibOrgBouncycastleAsn1X9X9ECParameters_(params);
    ecParameterSpec_ = new_LibOrgBouncycastleJceSpecECNamedCurveSpec_initWithNSString_withJavaSecuritySpecEllipticCurve_withJavaSecuritySpecECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(curveName_, [((JavaSecuritySpecECParameterSpec *) nil_chk(baseSpec)) getCurve], [baseSpec getGenerator], [baseSpec getOrder], JavaMathBigInteger_valueOfWithLong_([baseSpec getCofactor]));
  }
  else if ([algorithmParameterSpec isKindOfClass:[JavaSecuritySpecECParameterSpec class]]) {
    if ([algorithmParameterSpec isKindOfClass:[LibOrgBouncycastleJceSpecECNamedCurveSpec class]]) {
      curveName_ = [((LibOrgBouncycastleJceSpecECNamedCurveSpec *) nil_chk(((LibOrgBouncycastleJceSpecECNamedCurveSpec *) algorithmParameterSpec))) getName];
    }
    else {
      curveName_ = nil;
    }
    ecParameterSpec_ = (JavaSecuritySpecECParameterSpec *) cast_chk(algorithmParameterSpec, [JavaSecuritySpecECParameterSpec class]);
  }
  else {
    @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(JreStrcat("$$", @"AlgorithmParameterSpec class not recognized: ", [[((id<JavaSecuritySpecAlgorithmParameterSpec>) nil_chk(algorithmParameterSpec)) java_getClass] getName]));
  }
}

- (void)engineInitWithByteArray:(IOSByteArray *)bytes {
  [self engineInitWithByteArray:bytes withNSString:@"ASN.1"];
}

- (void)engineInitWithByteArray:(IOSByteArray *)bytes
                   withNSString:(NSString *)format {
  if ([self isASN1FormatStringWithNSString:format]) {
    LibOrgBouncycastleAsn1X9X962Parameters *params = LibOrgBouncycastleAsn1X9X962Parameters_getInstanceWithId_(bytes);
    LibOrgBouncycastleMathEcECCurve *curve = LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_getCurveWithLibOrgBouncycastleJcajceProviderConfigProviderConfiguration_withLibOrgBouncycastleAsn1X9X962Parameters_(JreLoadStatic(LibOrgBouncycastleJceProviderBouncyCastleProvider, CONFIGURATION), params);
    if ([((LibOrgBouncycastleAsn1X9X962Parameters *) nil_chk(params)) isNamedCurve]) {
      LibOrgBouncycastleAsn1ASN1ObjectIdentifier *curveId = LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([params getParameters]);
      curveName_ = LibOrgBouncycastleAsn1X9ECNamedCurveTable_getNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(curveId);
      if (curveName_ == nil) {
        curveName_ = [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(curveId)) getId];
      }
    }
    ecParameterSpec_ = LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_convertToSpecWithLibOrgBouncycastleAsn1X9X962Parameters_withLibOrgBouncycastleMathEcECCurve_(params, curve);
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$$", @"Unknown encoded parameters format in AlgorithmParameters object: ", format));
  }
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)engineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec {
  if ([JavaSecuritySpecECParameterSpec_class_() isAssignableFrom:paramSpec] || paramSpec == JavaSecuritySpecAlgorithmParameterSpec_class_()) {
    return ecParameterSpec_;
  }
  else if ([JavaSecuritySpecECGenParameterSpec_class_() isAssignableFrom:paramSpec]) {
    if (curveName_ != nil) {
      LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurveOid = LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilECUtil_getNamedCurveOidWithNSString_(curveName_);
      if (namedCurveOid != nil) {
        return new_JavaSecuritySpecECGenParameterSpec_initWithNSString_([namedCurveOid getId]);
      }
      return new_JavaSecuritySpecECGenParameterSpec_initWithNSString_(curveName_);
    }
    else {
      LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurveOid = LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilECUtil_getNamedCurveOidWithLibOrgBouncycastleJceSpecECParameterSpec_(LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_convertSpecWithJavaSecuritySpecECParameterSpec_withBoolean_(ecParameterSpec_, false));
      if (namedCurveOid != nil) {
        return new_JavaSecuritySpecECGenParameterSpec_initWithNSString_([namedCurveOid getId]);
      }
    }
  }
  @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(JreStrcat("$$", @"EC AlgorithmParameters cannot convert to ", [((IOSClass *) nil_chk(paramSpec)) getName]));
}

- (IOSByteArray *)engineGetEncoded {
  return [self engineGetEncodedWithNSString:@"ASN.1"];
}

- (IOSByteArray *)engineGetEncodedWithNSString:(NSString *)format {
  if ([self isASN1FormatStringWithNSString:format]) {
    LibOrgBouncycastleAsn1X9X962Parameters *params;
    if (ecParameterSpec_ == nil) {
      params = new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1Null_(JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE));
    }
    else if (curveName_ != nil) {
      params = new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleJcajceProviderAsymmetricUtilJcajceUtilECUtil_getNamedCurveOidWithNSString_(curveName_));
    }
    else {
      LibOrgBouncycastleJceSpecECParameterSpec *ecSpec = LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_convertSpecWithJavaSecuritySpecECParameterSpec_withBoolean_(ecParameterSpec_, false);
      LibOrgBouncycastleAsn1X9X9ECParameters *ecP = new_LibOrgBouncycastleAsn1X9X9ECParameters_initWithLibOrgBouncycastleMathEcECCurve_withLibOrgBouncycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_([((LibOrgBouncycastleJceSpecECParameterSpec *) nil_chk(ecSpec)) getCurve], [ecSpec getG], [ecSpec getN], [ecSpec getH], [ecSpec getSeed]);
      params = new_LibOrgBouncycastleAsn1X9X962Parameters_initWithLibOrgBouncycastleAsn1X9X9ECParameters_(ecP);
    }
    return [params getEncoded];
  }
  @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$$", @"Unknown parameters format in AlgorithmParameters object: ", format));
}

- (NSString *)engineToString {
  return @"EC AlgorithmParameters ";
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x4, 2, 3, 4, -1, -1, -1 },
    { NULL, "V", 0x4, 2, 5, 6, -1, -1, -1 },
    { NULL, "V", 0x4, 2, 7, 6, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x4, 8, 9, 4, 10, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, 6, -1, -1, -1 },
    { NULL, "[B", 0x4, 11, 1, 6, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isASN1FormatStringWithNSString:);
  methods[2].selector = @selector(engineInitWithJavaSecuritySpecAlgorithmParameterSpec:);
  methods[3].selector = @selector(engineInitWithByteArray:);
  methods[4].selector = @selector(engineInitWithByteArray:withNSString:);
  methods[5].selector = @selector(engineGetParameterSpecWithIOSClass:);
  methods[6].selector = @selector(engineGetEncoded);
  methods[7].selector = @selector(engineGetEncodedWithNSString:);
  methods[8].selector = @selector(engineToString);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ecParameterSpec_", "LJavaSecuritySpecECParameterSpec;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "curveName_", "LNSString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "isASN1FormatString", "LNSString;", "engineInit", "LJavaSecuritySpecAlgorithmParameterSpec;", "LJavaSecuritySpecInvalidParameterSpecException;", "[B", "LJavaIoIOException;", "[BLNSString;", "engineGetParameterSpec", "LIOSClass;", "<T::Ljava/security/spec/AlgorithmParameterSpec;>(Ljava/lang/Class<TT;>;)TT;", "engineGetEncoded" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi = { "EcAlgorithmParametersSpi", "lib.org.bouncycastle.jcajce.provider.asymmetric.ec", ptrTable, methods, fields, 7, 0x1, 9, 2, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi *self) {
  JavaSecurityAlgorithmParametersSpi_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricEcEcAlgorithmParametersSpi)
