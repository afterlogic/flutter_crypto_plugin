//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/x509/X509CertPairStoreSelector.java
//

#include "J2ObjC_source.h"
#include "X509CertPairStoreSelector.h"
#include "X509CertStoreSelector.h"
#include "X509CertificatePair.h"
#include "java/lang/Exception.h"
#include "java/security/cert/X509Certificate.h"

@interface LibOrgBouncycastleX509X509CertPairStoreSelector () {
 @public
  LibOrgBouncycastleX509X509CertStoreSelector *forwardSelector_;
  LibOrgBouncycastleX509X509CertStoreSelector *reverseSelector_;
  LibOrgBouncycastleX509X509CertificatePair *certPair_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509X509CertPairStoreSelector, forwardSelector_, LibOrgBouncycastleX509X509CertStoreSelector *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509X509CertPairStoreSelector, reverseSelector_, LibOrgBouncycastleX509X509CertStoreSelector *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleX509X509CertPairStoreSelector, certPair_, LibOrgBouncycastleX509X509CertificatePair *)

@implementation LibOrgBouncycastleX509X509CertPairStoreSelector

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleX509X509CertPairStoreSelector_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleX509X509CertificatePair *)getCertPair {
  return certPair_;
}

- (void)setCertPairWithLibOrgBouncycastleX509X509CertificatePair:(LibOrgBouncycastleX509X509CertificatePair *)certPair {
  self->certPair_ = certPair;
}

- (void)setForwardSelectorWithLibOrgBouncycastleX509X509CertStoreSelector:(LibOrgBouncycastleX509X509CertStoreSelector *)forwardSelector {
  self->forwardSelector_ = forwardSelector;
}

- (void)setReverseSelectorWithLibOrgBouncycastleX509X509CertStoreSelector:(LibOrgBouncycastleX509X509CertStoreSelector *)reverseSelector {
  self->reverseSelector_ = reverseSelector;
}

- (id)java_clone {
  LibOrgBouncycastleX509X509CertPairStoreSelector *cln = new_LibOrgBouncycastleX509X509CertPairStoreSelector_init();
  cln->certPair_ = certPair_;
  if (forwardSelector_ != nil) {
    [cln setForwardSelectorWithLibOrgBouncycastleX509X509CertStoreSelector:(LibOrgBouncycastleX509X509CertStoreSelector *) cast_chk([forwardSelector_ java_clone], [LibOrgBouncycastleX509X509CertStoreSelector class])];
  }
  if (reverseSelector_ != nil) {
    [cln setReverseSelectorWithLibOrgBouncycastleX509X509CertStoreSelector:(LibOrgBouncycastleX509X509CertStoreSelector *) cast_chk([reverseSelector_ java_clone], [LibOrgBouncycastleX509X509CertStoreSelector class])];
  }
  return cln;
}

- (jboolean)matchWithId:(id)obj {
  @try {
    if (!([obj isKindOfClass:[LibOrgBouncycastleX509X509CertificatePair class]])) {
      return false;
    }
    LibOrgBouncycastleX509X509CertificatePair *pair = (LibOrgBouncycastleX509X509CertificatePair *) cast_chk(obj, [LibOrgBouncycastleX509X509CertificatePair class]);
    if (forwardSelector_ != nil && ![forwardSelector_ matchWithId:[((LibOrgBouncycastleX509X509CertificatePair *) nil_chk(pair)) getForward]]) {
      return false;
    }
    if (reverseSelector_ != nil && ![reverseSelector_ matchWithId:[((LibOrgBouncycastleX509X509CertificatePair *) nil_chk(pair)) getReverse]]) {
      return false;
    }
    if (certPair_ != nil) {
      return [certPair_ isEqual:obj];
    }
    return true;
  }
  @catch (JavaLangException *e) {
    return false;
  }
}

- (LibOrgBouncycastleX509X509CertStoreSelector *)getForwardSelector {
  return forwardSelector_;
}

- (LibOrgBouncycastleX509X509CertStoreSelector *)getReverseSelector {
  return reverseSelector_;
}

- (id)clone {
  return [self java_clone];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleX509X509CertificatePair;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 3, -1, -1, -1, -1 },
    { NULL, "LNSObject;", 0x1, 5, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleX509X509CertStoreSelector;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleX509X509CertStoreSelector;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getCertPair);
  methods[2].selector = @selector(setCertPairWithLibOrgBouncycastleX509X509CertificatePair:);
  methods[3].selector = @selector(setForwardSelectorWithLibOrgBouncycastleX509X509CertStoreSelector:);
  methods[4].selector = @selector(setReverseSelectorWithLibOrgBouncycastleX509X509CertStoreSelector:);
  methods[5].selector = @selector(java_clone);
  methods[6].selector = @selector(matchWithId:);
  methods[7].selector = @selector(getForwardSelector);
  methods[8].selector = @selector(getReverseSelector);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "forwardSelector_", "LLibOrgBouncycastleX509X509CertStoreSelector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "reverseSelector_", "LLibOrgBouncycastleX509X509CertStoreSelector;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "certPair_", "LLibOrgBouncycastleX509X509CertificatePair;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "setCertPair", "LLibOrgBouncycastleX509X509CertificatePair;", "setForwardSelector", "LLibOrgBouncycastleX509X509CertStoreSelector;", "setReverseSelector", "clone", "match", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleX509X509CertPairStoreSelector = { "X509CertPairStoreSelector", "lib.org.bouncycastle.x509", ptrTable, methods, fields, 7, 0x1, 9, 3, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleX509X509CertPairStoreSelector;
}

- (id)copyWithZone:(NSZone *)zone {
  return [self java_clone];
}

@end

void LibOrgBouncycastleX509X509CertPairStoreSelector_init(LibOrgBouncycastleX509X509CertPairStoreSelector *self) {
  NSObject_init(self);
}

LibOrgBouncycastleX509X509CertPairStoreSelector *new_LibOrgBouncycastleX509X509CertPairStoreSelector_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleX509X509CertPairStoreSelector, init)
}

LibOrgBouncycastleX509X509CertPairStoreSelector *create_LibOrgBouncycastleX509X509CertPairStoreSelector_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleX509X509CertPairStoreSelector, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleX509X509CertPairStoreSelector)
