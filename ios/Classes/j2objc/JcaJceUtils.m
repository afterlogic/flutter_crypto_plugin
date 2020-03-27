//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/util/JcaJceUtils.java
//

#include "ASN1Encodable.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1Primitive.h"
#include "CryptoProObjectIdentifiers.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaJceUtils.h"
#include "NISTObjectIdentifiers.h"
#include "OIWObjectIdentifiers.h"
#include "PKCSObjectIdentifiers.h"
#include "TeleTrusTObjectIdentifiers.h"
#include "java/lang/Exception.h"
#include "java/security/AlgorithmParameters.h"

@interface LibOrgBouncycastleJcajceUtilJcaJceUtils ()

- (instancetype)init;

@end

__attribute__((unused)) static void LibOrgBouncycastleJcajceUtilJcaJceUtils_init(LibOrgBouncycastleJcajceUtilJcaJceUtils *self);

__attribute__((unused)) static LibOrgBouncycastleJcajceUtilJcaJceUtils *new_LibOrgBouncycastleJcajceUtilJcaJceUtils_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleJcajceUtilJcaJceUtils *create_LibOrgBouncycastleJcajceUtilJcaJceUtils_init(void);

@implementation LibOrgBouncycastleJcajceUtilJcaJceUtils

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceUtilJcaJceUtils_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (id<LibOrgBouncycastleAsn1ASN1Encodable>)extractParametersWithJavaSecurityAlgorithmParameters:(JavaSecurityAlgorithmParameters *)params {
  return LibOrgBouncycastleJcajceUtilJcaJceUtils_extractParametersWithJavaSecurityAlgorithmParameters_(params);
}

+ (void)loadParametersWithJavaSecurityAlgorithmParameters:(JavaSecurityAlgorithmParameters *)params
                  withLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)sParams {
  LibOrgBouncycastleJcajceUtilJcaJceUtils_loadParametersWithJavaSecurityAlgorithmParameters_withLibOrgBouncycastleAsn1ASN1Encodable_(params, sParams);
}

+ (NSString *)getDigestAlgNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)digestAlgOID {
  return LibOrgBouncycastleJcajceUtilJcaJceUtils_getDigestAlgNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(digestAlgOID);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x9, 0, 1, 2, -1, -1, -1 },
    { NULL, "V", 0x9, 3, 4, 2, -1, -1, -1 },
    { NULL, "LNSString;", 0x9, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(extractParametersWithJavaSecurityAlgorithmParameters:);
  methods[2].selector = @selector(loadParametersWithJavaSecurityAlgorithmParameters:withLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[3].selector = @selector(getDigestAlgNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "extractParameters", "LJavaSecurityAlgorithmParameters;", "LJavaIoIOException;", "loadParameters", "LJavaSecurityAlgorithmParameters;LLibOrgBouncycastleAsn1ASN1Encodable;", "getDigestAlgName", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceUtilJcaJceUtils = { "JcaJceUtils", "lib.org.bouncycastle.jcajce.util", ptrTable, methods, NULL, 7, 0x1, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceUtilJcaJceUtils;
}

@end

void LibOrgBouncycastleJcajceUtilJcaJceUtils_init(LibOrgBouncycastleJcajceUtilJcaJceUtils *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJcajceUtilJcaJceUtils *new_LibOrgBouncycastleJcajceUtilJcaJceUtils_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceUtilJcaJceUtils, init)
}

LibOrgBouncycastleJcajceUtilJcaJceUtils *create_LibOrgBouncycastleJcajceUtilJcaJceUtils_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceUtilJcaJceUtils, init)
}

id<LibOrgBouncycastleAsn1ASN1Encodable> LibOrgBouncycastleJcajceUtilJcaJceUtils_extractParametersWithJavaSecurityAlgorithmParameters_(JavaSecurityAlgorithmParameters *params) {
  LibOrgBouncycastleJcajceUtilJcaJceUtils_initialize();
  id<LibOrgBouncycastleAsn1ASN1Encodable> asn1Params;
  @try {
    asn1Params = LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_([((JavaSecurityAlgorithmParameters *) nil_chk(params)) getEncodedWithNSString:@"ASN.1"]);
  }
  @catch (JavaLangException *ex) {
    asn1Params = LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_([params getEncoded]);
  }
  return asn1Params;
}

void LibOrgBouncycastleJcajceUtilJcaJceUtils_loadParametersWithJavaSecurityAlgorithmParameters_withLibOrgBouncycastleAsn1ASN1Encodable_(JavaSecurityAlgorithmParameters *params, id<LibOrgBouncycastleAsn1ASN1Encodable> sParams) {
  LibOrgBouncycastleJcajceUtilJcaJceUtils_initialize();
  @try {
    [((JavaSecurityAlgorithmParameters *) nil_chk(params)) init__WithByteArray:[((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([((id<LibOrgBouncycastleAsn1ASN1Encodable>) nil_chk(sParams)) toASN1Primitive])) getEncoded] withNSString:@"ASN.1"];
  }
  @catch (JavaLangException *ex) {
    [params init__WithByteArray:[((LibOrgBouncycastleAsn1ASN1Primitive *) nil_chk([sParams toASN1Primitive])) getEncoded]];
  }
}

NSString *LibOrgBouncycastleJcajceUtilJcaJceUtils_getDigestAlgNameWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *digestAlgOID) {
  LibOrgBouncycastleJcajceUtilJcaJceUtils_initialize();
  if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1PkcsPKCSObjectIdentifiers, md5))) isEqual:digestAlgOID]) {
    return @"MD5";
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1OiwOIWObjectIdentifiers, idSHA1))) isEqual:digestAlgOID]) {
    return @"SHA1";
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha224))) isEqual:digestAlgOID]) {
    return @"SHA224";
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha256))) isEqual:digestAlgOID]) {
    return @"SHA256";
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha384))) isEqual:digestAlgOID]) {
    return @"SHA384";
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1NistNISTObjectIdentifiers, id_sha512))) isEqual:digestAlgOID]) {
    return @"SHA512";
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1TeletrustTeleTrusTObjectIdentifiers, ripemd128))) isEqual:digestAlgOID]) {
    return @"RIPEMD128";
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1TeletrustTeleTrusTObjectIdentifiers, ripemd160))) isEqual:digestAlgOID]) {
    return @"RIPEMD160";
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1TeletrustTeleTrusTObjectIdentifiers, ripemd256))) isEqual:digestAlgOID]) {
    return @"RIPEMD256";
  }
  else if ([((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(JreLoadStatic(LibOrgBouncycastleAsn1CryptoproCryptoProObjectIdentifiers, gostR3411))) isEqual:digestAlgOID]) {
    return @"GOST3411";
  }
  else {
    return [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(digestAlgOID)) getId];
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceUtilJcaJceUtils)
