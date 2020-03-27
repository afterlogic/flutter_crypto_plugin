//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/ValidityPrecompInfo.java
//

#include "J2ObjC_source.h"
#include "ValidityPrecompInfo.h"

@interface LibOrgBouncycastleMathEcValidityPrecompInfo () {
 @public
  jboolean failed_;
  jboolean curveEquationPassed_;
  jboolean orderPassed_;
}

@end

NSString *LibOrgBouncycastleMathEcValidityPrecompInfo_PRECOMP_NAME = @"bc_validity";

@implementation LibOrgBouncycastleMathEcValidityPrecompInfo

+ (NSString *)PRECOMP_NAME {
  return LibOrgBouncycastleMathEcValidityPrecompInfo_PRECOMP_NAME;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcValidityPrecompInfo_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (jboolean)hasFailed {
  return failed_;
}

- (void)reportFailed {
  failed_ = true;
}

- (jboolean)hasCurveEquationPassed {
  return curveEquationPassed_;
}

- (void)reportCurveEquationPassed {
  curveEquationPassed_ = true;
}

- (jboolean)hasOrderPassed {
  return orderPassed_;
}

- (void)reportOrderPassed {
  orderPassed_ = true;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(hasFailed);
  methods[2].selector = @selector(reportFailed);
  methods[3].selector = @selector(hasCurveEquationPassed);
  methods[4].selector = @selector(reportCurveEquationPassed);
  methods[5].selector = @selector(hasOrderPassed);
  methods[6].selector = @selector(reportOrderPassed);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "PRECOMP_NAME", "LNSString;", .constantValue.asLong = 0, 0x18, -1, 0, -1, -1 },
    { "failed_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "curveEquationPassed_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "orderPassed_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { &LibOrgBouncycastleMathEcValidityPrecompInfo_PRECOMP_NAME };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcValidityPrecompInfo = { "ValidityPrecompInfo", "lib.org.bouncycastle.math.ec", ptrTable, methods, fields, 7, 0x0, 7, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcValidityPrecompInfo;
}

@end

void LibOrgBouncycastleMathEcValidityPrecompInfo_init(LibOrgBouncycastleMathEcValidityPrecompInfo *self) {
  NSObject_init(self);
  self->failed_ = false;
  self->curveEquationPassed_ = false;
  self->orderPassed_ = false;
}

LibOrgBouncycastleMathEcValidityPrecompInfo *new_LibOrgBouncycastleMathEcValidityPrecompInfo_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcValidityPrecompInfo, init)
}

LibOrgBouncycastleMathEcValidityPrecompInfo *create_LibOrgBouncycastleMathEcValidityPrecompInfo_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcValidityPrecompInfo, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcValidityPrecompInfo)
