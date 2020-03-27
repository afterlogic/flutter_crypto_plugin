//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/rsa/RsaAlgorithmParametersSpi.java
//

#include "ASN1Encodable.h"
#include "ASN1Encoding.h"
#include "ASN1Integer.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "AlgorithmIdentifier.h"
#include "DERNull.h"
#include "DEROctetString.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MessageDigestUtils.h"
#include "PKCSObjectIdentifiers.h"
#include "RSAESOAEPparams.h"
#include "RSASSAPSSparams.h"
#include "RsaAlgorithmParametersSpi.h"
#include "java/io/IOException.h"
#include "java/lang/ArrayIndexOutOfBoundsException.h"
#include "java/lang/ClassCastException.h"
#include "java/lang/NullPointerException.h"
#include "java/lang/RuntimeException.h"
#include "java/math/BigInteger.h"
#include "java/security/AlgorithmParametersSpi.h"
#include "java/security/spec/AlgorithmParameterSpec.h"
#include "java/security/spec/InvalidParameterSpecException.h"
#include "java/security/spec/MGF1ParameterSpec.h"
#include "java/security/spec/PSSParameterSpec.h"
#include "javax/crypto/spec/OAEPParameterSpec.h"
#include "javax/crypto/spec/PSource.h"
#include "jcaJceUtilDigestFactory.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_init(self);
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

- (id<JavaSecuritySpecAlgorithmParameterSpec>)localEngineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x4, 2, 3, 4, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x404, 5, 3, 4, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(isASN1FormatStringWithNSString:);
  methods[2].selector = @selector(engineGetParameterSpecWithIOSClass:);
  methods[3].selector = @selector(localEngineGetParameterSpecWithIOSClass:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "isASN1FormatString", "LNSString;", "engineGetParameterSpec", "LIOSClass;", "LJavaSecuritySpecInvalidParameterSpecException;", "localEngineGetParameterSpec", "LLibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP;LLibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi = { "RsaAlgorithmParametersSpi", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, NULL, 7, 0x401, 4, 0, -1, 6, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi *self) {
  JavaSecurityAlgorithmParametersSpi_init(self);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)engineGetEncoded {
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_getOIDWithNSString_([((JavaxCryptoSpecOAEPParameterSpec *) nil_chk(currentSpec_)) getDigestAlgorithm]), JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE));
  JavaSecuritySpecMGF1ParameterSpec *mgfSpec = (JavaSecuritySpecMGF1ParameterSpec *) cast_chk([((JavaxCryptoSpecOAEPParameterSpec *) nil_chk(currentSpec_)) getMGFParameters], [JavaSecuritySpecMGF1ParameterSpec class]);
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *maskGenAlgorithm = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, id_mgf1), new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_getOIDWithNSString_([((JavaSecuritySpecMGF1ParameterSpec *) nil_chk(mgfSpec)) getDigestAlgorithm]), JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE)));
  JavaxCryptoSpecPSource_PSpecified *pSource = (JavaxCryptoSpecPSource_PSpecified *) cast_chk([((JavaxCryptoSpecOAEPParameterSpec *) nil_chk(currentSpec_)) getPSource], [JavaxCryptoSpecPSource_PSpecified class]);
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *pSourceAlgorithm = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, id_pSpecified), new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_([((JavaxCryptoSpecPSource_PSpecified *) nil_chk(pSource)) getValue]));
  LibOrgBouncycastleAsn1PkcsRSAESOAEPparams *oaepP = new_LibOrgBouncycastleAsn1PkcsRSAESOAEPparams_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_(hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm);
  @try {
    return [oaepP getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaLangRuntimeException_initWithNSString_(@"Error encoding OAEPParameters");
  }
}

- (IOSByteArray *)engineGetEncodedWithNSString:(NSString *)format {
  if ([self isASN1FormatStringWithNSString:format] || [((NSString *) nil_chk(format)) java_equalsIgnoreCase:@"X.509"]) {
    return [self engineGetEncoded];
  }
  return nil;
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)localEngineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec {
  if (paramSpec == JavaxCryptoSpecOAEPParameterSpec_class_() || paramSpec == JavaSecuritySpecAlgorithmParameterSpec_class_()) {
    return currentSpec_;
  }
  @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(@"unknown parameter spec passed to OAEP parameters object.");
}

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)paramSpec {
  if (!([paramSpec isKindOfClass:[JavaxCryptoSpecOAEPParameterSpec class]])) {
    @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(@"OAEPParameterSpec required to initialise an OAEP algorithm parameters object");
  }
  self->currentSpec_ = (JavaxCryptoSpecOAEPParameterSpec *) cast_chk(paramSpec, [JavaxCryptoSpecOAEPParameterSpec class]);
}

- (void)engineInitWithByteArray:(IOSByteArray *)params {
  @try {
    LibOrgBouncycastleAsn1PkcsRSAESOAEPparams *oaepP = LibOrgBouncycastleAsn1PkcsRSAESOAEPparams_getInstanceWithId_(params);
    if (![((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1PkcsRSAESOAEPparams *) nil_chk(oaepP)) getMaskGenAlgorithm])) getAlgorithm])) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, id_mgf1)]) {
      @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$@", @"unknown mask generation function: ", [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([oaepP getMaskGenAlgorithm])) getAlgorithm]));
    }
    currentSpec_ = new_JavaxCryptoSpecOAEPParameterSpec_initWithNSString_withNSString_withJavaSecuritySpecAlgorithmParameterSpec_withJavaxCryptoSpecPSource_(LibOrgBouncycastleJcajceUtilMessageDigestUtils_getDigestNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([oaepP getHashAlgorithm])) getAlgorithm]), [((JavaxCryptoSpecOAEPParameterSpec *) nil_chk(JreLoadStatic(JavaxCryptoSpecOAEPParameterSpec, DEFAULT))) getMGFAlgorithm], new_JavaSecuritySpecMGF1ParameterSpec_initWithNSString_(LibOrgBouncycastleJcajceUtilMessageDigestUtils_getDigestNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk(LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([oaepP getMaskGenAlgorithm])) getParameters]))) getAlgorithm])), new_JavaxCryptoSpecPSource_PSpecified_initWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([oaepP getPSourceAlgorithm])) getParameters]))) getOctets]));
  }
  @catch (JavaLangClassCastException *e) {
    @throw new_JavaIoIOException_initWithNSString_(@"Not a valid OAEP Parameter encoding.");
  }
  @catch (JavaLangArrayIndexOutOfBoundsException *e) {
    @throw new_JavaIoIOException_initWithNSString_(@"Not a valid OAEP Parameter encoding.");
  }
}

- (void)engineInitWithByteArray:(IOSByteArray *)params
                   withNSString:(NSString *)format {
  if ([((NSString *) nil_chk(format)) java_equalsIgnoreCase:@"X.509"] || [format java_equalsIgnoreCase:@"ASN.1"]) {
    [self engineInitWithByteArray:params];
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$$", @"Unknown parameter format ", format));
  }
}

- (NSString *)engineToString {
  return @"OAEP Parameters";
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x4, 2, 3, 4, -1, -1, -1 },
    { NULL, "V", 0x4, 5, 6, 4, -1, -1, -1 },
    { NULL, "V", 0x4, 5, 7, 8, -1, -1, -1 },
    { NULL, "V", 0x4, 5, 9, 8, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineGetEncoded);
  methods[2].selector = @selector(engineGetEncodedWithNSString:);
  methods[3].selector = @selector(localEngineGetParameterSpecWithIOSClass:);
  methods[4].selector = @selector(engineInitWithJavaSecuritySpecAlgorithmParameterSpec:);
  methods[5].selector = @selector(engineInitWithByteArray:);
  methods[6].selector = @selector(engineInitWithByteArray:withNSString:);
  methods[7].selector = @selector(engineToString);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "currentSpec_", "LJavaxCryptoSpecOAEPParameterSpec;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "engineGetEncoded", "LNSString;", "localEngineGetParameterSpec", "LIOSClass;", "LJavaSecuritySpecInvalidParameterSpecException;", "engineInit", "LJavaSecuritySpecAlgorithmParameterSpec;", "[B", "LJavaIoIOException;", "[BLNSString;", "LLibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP = { "OAEP", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, fields, 7, 0x9, 8, 1, 10, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_OAEP)

@implementation LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)engineGetEncoded {
  JavaSecuritySpecPSSParameterSpec *pssSpec = currentSpec_;
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *hashAlgorithm = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_getOIDWithNSString_([((JavaSecuritySpecPSSParameterSpec *) nil_chk(pssSpec)) getDigestAlgorithm]), JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE));
  JavaSecuritySpecMGF1ParameterSpec *mgfSpec = (JavaSecuritySpecMGF1ParameterSpec *) cast_chk([pssSpec getMGFParameters], [JavaSecuritySpecMGF1ParameterSpec class]);
  LibOrgBouncycastleAsn1X509AlgorithmIdentifier *maskGenAlgorithm = new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, id_mgf1), new_LibOrgBouncycastleAsn1X509AlgorithmIdentifier_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleJcajceProviderUtiljcaJceUtilDigestFactory_getOIDWithNSString_([((JavaSecuritySpecMGF1ParameterSpec *) nil_chk(mgfSpec)) getDigestAlgorithm]), JreLoadStatic(LibOrgBouncycastleAsn1DERNull, INSTANCE)));
  LibOrgBouncycastleAsn1PkcsRSASSAPSSparams *pssP = new_LibOrgBouncycastleAsn1PkcsRSASSAPSSparams_initWithLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1X509AlgorithmIdentifier_withLibOrgBouncycastleAsn1ASN1Integer_withLibOrgBouncycastleAsn1ASN1Integer_(hashAlgorithm, maskGenAlgorithm, new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_([pssSpec getSaltLength]), new_LibOrgBouncycastleAsn1ASN1Integer_initWithLong_([pssSpec getTrailerField]));
  return [pssP getEncodedWithNSString:@"DER"];
}

- (IOSByteArray *)engineGetEncodedWithNSString:(NSString *)format {
  if ([((NSString *) nil_chk(format)) java_equalsIgnoreCase:@"X.509"] || [format java_equalsIgnoreCase:@"ASN.1"]) {
    return [self engineGetEncoded];
  }
  return nil;
}

- (id<JavaSecuritySpecAlgorithmParameterSpec>)localEngineGetParameterSpecWithIOSClass:(IOSClass *)paramSpec {
  if (paramSpec == JavaSecuritySpecPSSParameterSpec_class_() || paramSpec == JavaSecuritySpecAlgorithmParameterSpec_class_()) {
    return currentSpec_;
  }
  @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(@"unknown parameter spec passed to PSS parameters object.");
}

- (void)engineInitWithJavaSecuritySpecAlgorithmParameterSpec:(id<JavaSecuritySpecAlgorithmParameterSpec>)paramSpec {
  if (!([paramSpec isKindOfClass:[JavaSecuritySpecPSSParameterSpec class]])) {
    @throw new_JavaSecuritySpecInvalidParameterSpecException_initWithNSString_(@"PSSParameterSpec required to initialise an PSS algorithm parameters object");
  }
  self->currentSpec_ = (JavaSecuritySpecPSSParameterSpec *) cast_chk(paramSpec, [JavaSecuritySpecPSSParameterSpec class]);
}

- (void)engineInitWithByteArray:(IOSByteArray *)params {
  @try {
    LibOrgBouncycastleAsn1PkcsRSASSAPSSparams *pssP = LibOrgBouncycastleAsn1PkcsRSASSAPSSparams_getInstanceWithId_(params);
    if (![((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([((LibOrgBouncycastleAsn1PkcsRSASSAPSSparams *) nil_chk(pssP)) getMaskGenAlgorithm])) getAlgorithm])) isEqual:JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, id_mgf1)]) {
      @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$@", @"unknown mask generation function: ", [((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([pssP getMaskGenAlgorithm])) getAlgorithm]));
    }
    currentSpec_ = new_JavaSecuritySpecPSSParameterSpec_initWithNSString_withNSString_withJavaSecuritySpecAlgorithmParameterSpec_withInt_withInt_(LibOrgBouncycastleJcajceUtilMessageDigestUtils_getDigestNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([pssP getHashAlgorithm])) getAlgorithm]), [((JavaSecuritySpecPSSParameterSpec *) nil_chk(JreLoadStatic(JavaSecuritySpecPSSParameterSpec, DEFAULT))) getMGFAlgorithm], new_JavaSecuritySpecMGF1ParameterSpec_initWithNSString_(LibOrgBouncycastleJcajceUtilMessageDigestUtils_getDigestNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk(LibOrgBouncycastleAsn1X509AlgorithmIdentifier_getInstanceWithId_([((LibOrgBouncycastleAsn1X509AlgorithmIdentifier *) nil_chk([pssP getMaskGenAlgorithm])) getParameters]))) getAlgorithm])), [((JavaMathBigInteger *) nil_chk([pssP getSaltLength])) intValue], [((JavaMathBigInteger *) nil_chk([pssP getTrailerField])) intValue]);
  }
  @catch (JavaLangClassCastException *e) {
    @throw new_JavaIoIOException_initWithNSString_(@"Not a valid PSS Parameter encoding.");
  }
  @catch (JavaLangArrayIndexOutOfBoundsException *e) {
    @throw new_JavaIoIOException_initWithNSString_(@"Not a valid PSS Parameter encoding.");
  }
}

- (void)engineInitWithByteArray:(IOSByteArray *)params
                   withNSString:(NSString *)format {
  if ([self isASN1FormatStringWithNSString:format] || [((NSString *) nil_chk(format)) java_equalsIgnoreCase:@"X.509"]) {
    [self engineInitWithByteArray:params];
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$$", @"Unknown parameter format ", format));
  }
}

- (NSString *)engineToString {
  return @"PSS Parameters";
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, 0, -1, -1, -1 },
    { NULL, "[B", 0x4, 1, 2, 0, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecAlgorithmParameterSpec;", 0x4, 3, 4, 5, -1, -1, -1 },
    { NULL, "V", 0x4, 6, 7, 5, -1, -1, -1 },
    { NULL, "V", 0x4, 6, 8, 0, -1, -1, -1 },
    { NULL, "V", 0x4, 6, 9, 0, -1, -1, -1 },
    { NULL, "LNSString;", 0x4, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(engineGetEncoded);
  methods[2].selector = @selector(engineGetEncodedWithNSString:);
  methods[3].selector = @selector(localEngineGetParameterSpecWithIOSClass:);
  methods[4].selector = @selector(engineInitWithJavaSecuritySpecAlgorithmParameterSpec:);
  methods[5].selector = @selector(engineInitWithByteArray:);
  methods[6].selector = @selector(engineInitWithByteArray:withNSString:);
  methods[7].selector = @selector(engineToString);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "currentSpec_", "LJavaSecuritySpecPSSParameterSpec;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaIoIOException;", "engineGetEncoded", "LNSString;", "localEngineGetParameterSpec", "LIOSClass;", "LJavaSecuritySpecInvalidParameterSpecException;", "engineInit", "LJavaSecuritySpecAlgorithmParameterSpec;", "[B", "[BLNSString;", "LLibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS = { "PSS", "lib.org.bouncycastle.jcajce.provider.asymmetric.rsa", ptrTable, methods, fields, 7, 0x9, 8, 1, 10, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS_init(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS *new_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS *create_LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricRsaRsaAlgorithmParametersSpi_PSS)
