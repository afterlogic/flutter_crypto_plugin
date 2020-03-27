//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dh/DhAlgorithmParametersSpi.java
//

#include "ASN1Encoding.h"
#include "DHParameter.h"
#include "DhAlgorithmParametersSpi.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/IOException.h"
#include "java/lang/ArrayIndexOutOfBoundsException.h"
#include "java/lang/ClassCastException.h"
#include "java/lang/NullPointerException.h"
#include "java/lang/RuntimeException.h"
#include "java/math/BigInteger.h"
#include "java/security/AlgorithmParametersSpi.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "java/security/spec/InvalidParameterSpecException.h"
#include "javax/crypto/spec/DHParameterSpec.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)isASN1FormatStringWithNSString:(NSString *)format {
  return format == nil || [format isEqual:@"ASN.1"];
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)engineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec {
  if (paramSpec == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"argument to getParameterSpec must not be null");
  }
  return [self localEngineGetParameterSpecWithIOSClass:paramSpec];
}

- (IOSByteArray *)engineGetEncoded {
  LibOrgBouncycastleAsn1PkcsDHParameter *dhP = new_LibOrgBouncycastleAsn1PkcsDHParameter_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_([((JavaxCryptoSpecDHParameterSpec *) nil_chk(currentSpec_)) getP], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(currentSpec_)) getG], [((JavaxCryptoSpecDHParameterSpec *) nil_chk(currentSpec_)) getL]);
  @try {
    return [dhP getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"Error encoding DHParameters");
  }
}

- (IOSByteArray *)engineGetEncodedWithNSString:(NSString *)format {
  if ([self isASN1FormatStringWithNSString:format]) {
    return [self engineGetEncoded];
  }
  return nil;
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)localEngineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec {
  if (paramSpec == JavaxCryptoSpecDHParameterSpec_class_() || paramSpec == JavaSecuritySpecAlgorithmParameterSpec_class_()) {
    return currentSpec_;
  }
  @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(@"unknown parameter spec passed to DH parameters object.");
}

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)paramSpec {
  if (!([paramSpec isKindOfClass:[JavaxCryptoSpecDHParameterSpec class]])) {
    @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(@"DHParameterSpec required to initialise a Diffie-Hellman algorithm parameters object");
  }
  self->currentSpec_ = (JavaxCryptoSpecDHParameterSpec *) cast_chk(paramSpec, [JavaxCryptoSpecDHParameterSpec class]);
}

- (void)engineInitWithByteArray:(IOSByteArray *)params {
  @try {
    LibOrgBouncycastleAsn1PkcsDHParameter *dhP = LibOrgBouncycastleAsn1PkcsDHParameter_getInstanceWithId_(params);
    if ([((LibOrgBouncycastleAsn1PkcsDHParameter *) nil_chk(dhP)) getL] != nil) {
      currentSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_withInt_([dhP getP], [dhP getG], [((JavaMathBigInteger *) nil_chk([dhP getL])) intValue]);
    }
    else {
      currentSpec_ = new_JavaxCryptoSpecDHParameterSpec_initWithJavaMathBigInteger_withJavaMathBigInteger_([dhP getP], [dhP getG]);
    }
  }
  @catch (JavaLangClassCastException *e) {
    @throw new_JavaIoIOException_initWithNSString_(@"Not a valid DH Parameter encoding.");
  }
  @catch (JavaLangArrayIndexOutOfBoundsException *e) {
    @throw new_JavaIoIOException_initWithNSString_(@"Not a valid DH Parameter encoding.");
  }
}

- (void)engineInitWithByteArray:(IOSByteArray *)params
                   withNSString:(NSString *)format {
  if ([self isASN1FormatStringWithNSString:format]) {
    [self engineInitWithByteArray:params];
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$$", @"Unknown parameter format ", format));
  }
}

- (NSString *)engineToString {
  return @"Diffie-Hellman Parameters";
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x4, 2, 3, 4, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, 5, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x4, 6, 3, 4, -1, -1, -1 },
    { NULL, "V", 0x4, 7, 8, 4, -1, -1, -1 },
    { NULL, "V", 0x4, 7, 9, 10, -1, -1, -1 },
    { NULL, "V", 0x4, 7, 11, 10, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isASN1FormatStringWithNSString:);
  methods[2].selector = @selector(engineGetParameterSpecWithIOSClass:);
  methods[3].selector = @selector(engineGetEncoded);
  methods[4].selector = @selector(engineGetEncodedWithNSString:);
  methods[5].selector = @selector(localEngineGetParameterSpecWithIOSClass:);
  methods[6].selector = @selector(engineInitWithJavaSecuritySpecAlgorithmParameterSpec:);
  methods[7].selector = @selector(engineInitWithByteArray:);
  methods[8].selector = @selector(engineInitWithByteArray:withNSString:);
  methods[9].selector = @selector(engineToString);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "currentSpec_", "LJavaxCryptoSpecDHParameterSpec;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "isASN1FormatString", "LNSString;", "engineGetParameterSpec", "LIOSClass;", "LJavaSecuritySpecInvalidParameterSpecException;", "engineGetEncoded", "localEngineGetParameterSpec", "engineInit", "LJavaSecuritySpecAlgorithmParameterSpec;", "[B", "LJavaIoIOException;", "[BLNSString;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi = { "DhAlgorithmParametersSpi", "lib.org.bouncycastle.jcajce.provider.asymmetric.dh", ptrTable, methods, fields, 7, 0x1, 10, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi *self) {
  JavaSecurityAlgorithmParametersSpi_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi *new_LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi *create_LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDhDhAlgorithmParametersSpi)
