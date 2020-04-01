//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/xmss/WOTSPlusSignature.java
//

#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "WOTSPlusParameters.h"
#include "WOTSPlusSignature.h"
#include "XMSSUtil.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/NullPointerException.h"

@interface LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature () {
 @public
  IOSObjectArray *signature_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature, signature_, IOSObjectArray *)

@implementation LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature

- (instancetype)initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters:(LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *)params
                                                           withByteArray2:(IOSObjectArray *)signature {
  LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(self, params, signature);
  return self;
}

- (IOSObjectArray *)toByteArray {
  return LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray2_(signature_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "[[B", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters:withByteArray2:);
  methods[1].selector = @selector(toByteArray);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "signature_", "[[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters;[[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature = { "WOTSPlusSignature", "lib.org.bouncycastle.pqc.crypto.xmss", ptrTable, methods, fields, 7, 0x10, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature;
}

@end

void LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature *self, LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *params, IOSObjectArray *signature) {
  NSObject_init(self);
  if (params == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"params == null");
  }
  if (signature == nil) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"signature == null");
  }
  if (LibOrgBouncycastlePqcCryptoXmssXMSSUtil_hasNullPointerWithByteArray2_(signature)) {
    @throw new_JavaLangNullPointerException_initWithNSString_(@"signature byte array == null");
  }
  if (signature->size_ != [params getLen]) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong signature size");
  }
  for (jint i = 0; i < signature->size_; i++) {
    if (((IOSByteArray *) nil_chk(IOSObjectArray_Get(signature, i)))->size_ != [params getDigestSize]) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"wrong signature format");
    }
  }
  self->signature_ = LibOrgBouncycastlePqcCryptoXmssXMSSUtil_cloneArrayWithByteArray2_(signature);
}

LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature *new_LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *params, IOSObjectArray *signature) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature, initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_, params, signature)
}

LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature *create_LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature_initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_(LibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters *params, IOSObjectArray *signature) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature, initWithLibOrgBouncycastlePqcCryptoXmssWOTSPlusParameters_withByteArray2_, params, signature)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoXmssWOTSPlusSignature)