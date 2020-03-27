//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509CertificatePair.java
//

#include "ASN1Encoding.h"
#include "ASN1InputStream.h"
#include "ASN1Primitive.h"
#include "BCJcaJceHelper.h"
#include "CertificatePair.h"
#include "ExtCertificateEncodingException.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "JcaJceHelper.h"
#include "X509Certificate.h"
#include "X509CertificateObject.h"
#include "X509CertificatePair.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/security/cert/CertificateEncodingException.h"
#include "java/security/cert/X509Certificate.h"

@interface LibOrgBouncycastleX509X509CertificatePair () {
 @public
  id<LibOrgBouncycastleJcajceUtilJcaJceHelper> bcHelper_;
  JavaSecurityCertX509Certificate *forward_;
  JavaSecurityCertX509Certificate *reverse_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509X509CertificatePair, bcHelper_, id<LibOrgBouncycastleJcajceUtilJcaJceHelper>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509X509CertificatePair, forward_, JavaSecurityCertX509Certificate *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509X509CertificatePair, reverse_, JavaSecurityCertX509Certificate *)

@implementation LibOrgBouncycastleX509X509CertificatePair

- (instancetype)initWithJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)forward
                    withJavaSecurityCertX509Certificate:(JavaSecurityCertX509Certificate *)reverse {
  LibOrgBouncycastleX509X509CertificatePair_initWithJavaSecurityCertX509Certificate_withJavaSecurityCertX509Certificate_(self, forward, reverse);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1X509CertificatePair:(LibOrgBouncycastleAsn1X509CertificatePair *)pair {
  LibOrgBouncycastleX509X509CertificatePair_initWithLibOrgBouncycastleAsn1X509CertificatePair_(self, pair);
  return self;
}

- (IOSByteArray *)getEncoded {
  LibOrgBouncycastleAsn1X509X509Certificate *f = nil;
  LibOrgBouncycastleAsn1X509X509Certificate *r = nil;
  @try {
    if (forward_ != nil) {
      f = LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithId_([new_LibOrgBouncycastleAsn1ASN1InputStream_initWithByteArray_([forward_ getEncoded]) readObject]);
      if (f == nil) {
        @throw new_JavaSecurityCertCertificateEncodingException_initWithNSString_(@"unable to get encoding for forward");
      }
    }
    if (reverse_ != nil) {
      r = LibOrgBouncycastleAsn1X509X509Certificate_getInstanceWithId_([new_LibOrgBouncycastleAsn1ASN1InputStream_initWithByteArray_([reverse_ getEncoded]) readObject]);
      if (r == nil) {
        @throw new_JavaSecurityCertCertificateEncodingException_initWithNSString_(@"unable to get encoding for reverse");
      }
    }
    return [new_LibOrgBouncycastleAsn1X509CertificatePair_initWithLibOrgBouncycastleAsn1X509X509Certificate_withLibOrgBouncycastleAsn1X509X509Certificate_(f, r) getEncodedWithNSString:LibOrgBouncycastleAsn1ASN1Encoding_DER];
  }
  @catch (JavaLangIllegalArgumentException *e) {
    @throw new_LibOrgBouncycastleX509ExtCertificateEncodingException_initWithNSString_withJavaLangThrowable_([e description], e);
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleX509ExtCertificateEncodingException_initWithNSString_withJavaLangThrowable_([e description], e);
  }
}

- (JavaSecurityCertX509Certificate *)getForward {
  return forward_;
}

- (JavaSecurityCertX509Certificate *)getReverse {
  return reverse_;
}

- (jboolean)isEqual:(id)o {
  if (o == nil) {
    return false;
  }
  if (!([o isKindOfClass:[LibOrgBouncycastleX509X509CertificatePair class]])) {
    return false;
  }
  LibOrgBouncycastleX509X509CertificatePair *pair = (LibOrgBouncycastleX509X509CertificatePair *) cast_chk(o, [LibOrgBouncycastleX509X509CertificatePair class]);
  jboolean equalReverse = true;
  jboolean equalForward = true;
  if (forward_ != nil) {
    equalForward = [self->forward_ isEqual:pair->forward_];
  }
  else {
    if (pair->forward_ != nil) {
      equalForward = false;
    }
  }
  if (reverse_ != nil) {
    equalReverse = [self->reverse_ isEqual:pair->reverse_];
  }
  else {
    if (pair->reverse_ != nil) {
      equalReverse = false;
    }
  }
  return equalForward && equalReverse;
}

- (NSUInteger)hash {
  jint hash_ = -1;
  if (forward_ != nil) {
    hash_ ^= ((jint) [forward_ hash]);
  }
  if (reverse_ != nil) {
    hash_ *= 17;
    hash_ ^= ((jint) [reverse_ hash]);
  }
  return hash_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, 2, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, 3, -1, -1, -1 },
    { NULL, "LJavaSecurityCertX509Certificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecurityCertX509Certificate;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 6, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaSecurityCertX509Certificate:withJavaSecurityCertX509Certificate:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1X509CertificatePair:);
  methods[2].selector = @selector(getEncoded);
  methods[3].selector = @selector(getForward);
  methods[4].selector = @selector(getReverse);
  methods[5].selector = @selector(isEqual:);
  methods[6].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "bcHelper_", "LLibOrgBouncycastleJcajceUtilJcaJceHelper;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "forward_", "LJavaSecurityCertX509Certificate;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "reverse_", "LJavaSecurityCertX509Certificate;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaSecurityCertX509Certificate;LJavaSecurityCertX509Certificate;", "LLibOrgBouncycastleAsn1X509CertificatePair;", "LJavaSecurityCertCertificateParsingException;", "LJavaSecurityCertCertificateEncodingException;", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _LibOrgBouncycastleX509X509CertificatePair = { "X509CertificatePair", "lib.org.bouncycastle.x509", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleX509X509CertificatePair;
}

@end

void LibOrgBouncycastleX509X509CertificatePair_initWithJavaSecurityCertX509Certificate_withJavaSecurityCertX509Certificate_(LibOrgBouncycastleX509X509CertificatePair *self, JavaSecurityCertX509Certificate *forward, JavaSecurityCertX509Certificate *reverse) {
  NSObject_init(self);
  self->bcHelper_ = new_LibOrgBouncycastleJcajceUtilBCJcaJceHelper_init();
  self->forward_ = forward;
  self->reverse_ = reverse;
}

LibOrgBouncycastleX509X509CertificatePair *new_LibOrgBouncycastleX509X509CertificatePair_initWithJavaSecurityCertX509Certificate_withJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *forward, JavaSecurityCertX509Certificate *reverse) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleX509X509CertificatePair, initWithJavaSecurityCertX509Certificate_withJavaSecurityCertX509Certificate_, forward, reverse)
}

LibOrgBouncycastleX509X509CertificatePair *create_LibOrgBouncycastleX509X509CertificatePair_initWithJavaSecurityCertX509Certificate_withJavaSecurityCertX509Certificate_(JavaSecurityCertX509Certificate *forward, JavaSecurityCertX509Certificate *reverse) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleX509X509CertificatePair, initWithJavaSecurityCertX509Certificate_withJavaSecurityCertX509Certificate_, forward, reverse)
}

void LibOrgBouncycastleX509X509CertificatePair_initWithLibOrgBouncycastleAsn1X509CertificatePair_(LibOrgBouncycastleX509X509CertificatePair *self, LibOrgBouncycastleAsn1X509CertificatePair *pair) {
  NSObject_init(self);
  self->bcHelper_ = new_LibOrgBouncycastleJcajceUtilBCJcaJceHelper_init();
  if ([((LibOrgBouncycastleAsn1X509CertificatePair *) nil_chk(pair)) getForward] != nil) {
    self->forward_ = new_LibOrgBouncycastleJceProviderX509CertificateObject_initWithLibOrgBouncycastleAsn1X509X509Certificate_([pair getForward]);
  }
  if ([pair getReverse] != nil) {
    self->reverse_ = new_LibOrgBouncycastleJceProviderX509CertificateObject_initWithLibOrgBouncycastleAsn1X509X509Certificate_([pair getReverse]);
  }
}

LibOrgBouncycastleX509X509CertificatePair *new_LibOrgBouncycastleX509X509CertificatePair_initWithLibOrgBouncycastleAsn1X509CertificatePair_(LibOrgBouncycastleAsn1X509CertificatePair *pair) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleX509X509CertificatePair, initWithLibOrgBouncycastleAsn1X509CertificatePair_, pair)
}

LibOrgBouncycastleX509X509CertificatePair *create_LibOrgBouncycastleX509X509CertificatePair_initWithLibOrgBouncycastleAsn1X509CertificatePair_(LibOrgBouncycastleAsn1X509CertificatePair *pair) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleX509X509CertificatePair, initWithLibOrgBouncycastleAsn1X509CertificatePair_, pair)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleX509X509CertificatePair)
