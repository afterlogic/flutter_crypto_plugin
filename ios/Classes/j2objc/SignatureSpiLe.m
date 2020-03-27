//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/dstu/SignatureSpiLe.java
//

#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "DEROctetString.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcajceDstuSignatureSpi.h"
#include "SignatureSpiLe.h"
#include "java/io/IOException.h"
#include "java/lang/Exception.h"
#include "java/security/SignatureException.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)reverseBytesWithByteArray:(IOSByteArray *)bytes {
  jbyte tmp;
  for (jint i = 0; i < ((IOSByteArray *) nil_chk(bytes))->size_ / 2; i++) {
    tmp = IOSByteArray_Get(bytes, i);
    *IOSByteArray_GetRef(bytes, i) = IOSByteArray_Get(bytes, bytes->size_ - 1 - i);
    *IOSByteArray_GetRef(bytes, bytes->size_ - 1 - i) = tmp;
  }
}

- (IOSByteArray *)engineSign {
  IOSByteArray *signature = [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([super engineSign]))) getOctets];
  [self reverseBytesWithByteArray:signature];
  @try {
    return [(new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(signature)) getEncoded];
  }
  @catch (JavaLangException *e) {
    @throw new_JavaSecuritySignatureException_initWithNSString_([e description]);
  }
}

- (jboolean)engineVerifyWithByteArray:(IOSByteArray *)sigBytes {
  IOSByteArray *bytes = nil;
  @try {
    bytes = [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(((LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_(sigBytes), [LibOrgBouncycastleAsn1ASN1OctetString class])))) getOctets];
  }
  @catch (JavaIoIOException *e) {
    @throw new_JavaSecuritySignatureException_initWithNSString_(@"error decoding signature bytes.");
  }
  [self reverseBytesWithByteArray:bytes];
  @try {
    return [super engineVerifyWithByteArray:[(new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(bytes)) getEncoded]];
  }
  @catch (JavaSecuritySignatureException *e) {
    @throw e;
  }
  @catch (JavaLangException *e) {
    @throw new_JavaSecuritySignatureException_initWithNSString_([e description]);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 0, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x4, -1, -1, 2, -1, -1, -1 },
    { NULL, "Z", 0x4, 3, 1, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(reverseBytesWithByteArray:);
  methods[2].selector = @selector(engineSign);
  methods[3].selector = @selector(engineVerifyWithByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "reverseBytes", "[B", "LJavaSecuritySignatureException;", "engineVerify" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe = { "SignatureSpiLe", "lib.org.bouncycastle.jcajce.provider.asymmetric.dstu", ptrTable, methods, NULL, 7, 0x1, 4, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe_init(LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe *self) {
  LibOrgBouncycastleJcajceProviderAsymmetricDstuJcajceDstuSignatureSpi_init(self);
}

LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe *new_LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe, init)
}

LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe *create_LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricDstuSignatureSpiLe)
