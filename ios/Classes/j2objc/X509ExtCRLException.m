//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jcajce/provider/asymmetric/x509/X509ExtCRLException.java
//

#include "J2ObjC_source.h"
#include "X509ExtCRLException.h"
#include "java/lang/Throwable.h"
#include "java/security/cert/CRLException.h"

@implementation LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException

- (instancetype)initWithNSString:(NSString *)message
           withJavaLangThrowable:(JavaLangThrowable *)cause {
  LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException_initWithNSString_withJavaLangThrowable_(self, message, cause);
  return self;
}

- (JavaLangThrowable *)getCause {
  return cause_X509ExtCRLException_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaLangThrowable;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withJavaLangThrowable:);
  methods[1].selector = @selector(getCause);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cause_X509ExtCRLException_", "LJavaLangThrowable;", .constantValue.asLong = 0, 0x0, 1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LJavaLangThrowable;", "cause" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException = { "X509ExtCRLException", "lib.org.bouncycastle.jcajce.provider.asymmetric.x509", ptrTable, methods, fields, 7, 0x0, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException;
}

@end

void LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException_initWithNSString_withJavaLangThrowable_(LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException *self, NSString *message, JavaLangThrowable *cause) {
  JavaSecurityCertCRLException_initWithNSString_(self, message);
  self->cause_X509ExtCRLException_ = cause;
}

LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException *new_LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException, initWithNSString_withJavaLangThrowable_, message, cause)
}

LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException *create_LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException_initWithNSString_withJavaLangThrowable_(NSString *message, JavaLangThrowable *cause) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException, initWithNSString_withJavaLangThrowable_, message, cause)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJcajceProviderAsymmetricX509X509ExtCRLException)