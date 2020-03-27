//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/jce/ECPointUtil.java
//

#include "EC5Util.h"
#include "ECCurve.h"
#include "ECPoint.h"
#include "ECPointUtil.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "java/security/spec/ECField.h"
#include "java/security/spec/ECFieldF2m.h"
#include "java/security/spec/ECFieldFp.h"
#include "java/security/spec/ECPoint.h"
#include "java/security/spec/EllipticCurve.h"

@implementation LibOrgBouncycastleJceECPointUtil

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleJceECPointUtil_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (JavaSecuritySpecECPoint *)decodePointWithJavaSecuritySpecEllipticCurve:(JavaSecuritySpecEllipticCurve *)curve
                                                            withByteArray:(IOSByteArray *)encoded {
  return LibOrgBouncycastleJceECPointUtil_decodePointWithJavaSecuritySpecEllipticCurve_withByteArray_(curve, encoded);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaSecuritySpecECPoint;", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(decodePointWithJavaSecuritySpecEllipticCurve:withByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "decodePoint", "LJavaSecuritySpecEllipticCurve;[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastleJceECPointUtil = { "ECPointUtil", "lib.org.bouncycastle.jce", ptrTable, methods, NULL, 7, 0x1, 2, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleJceECPointUtil;
}

@end

void LibOrgBouncycastleJceECPointUtil_init(LibOrgBouncycastleJceECPointUtil *self) {
  NSObject_init(self);
}

LibOrgBouncycastleJceECPointUtil *new_LibOrgBouncycastleJceECPointUtil_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleJceECPointUtil, init)
}

LibOrgBouncycastleJceECPointUtil *create_LibOrgBouncycastleJceECPointUtil_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleJceECPointUtil, init)
}

JavaSecuritySpecECPoint *LibOrgBouncycastleJceECPointUtil_decodePointWithJavaSecuritySpecEllipticCurve_withByteArray_(JavaSecuritySpecEllipticCurve *curve, IOSByteArray *encoded) {
  LibOrgBouncycastleJceECPointUtil_initialize();
  LibOrgBouncycastleMathEcECCurve *c = nil;
  if ([[((JavaSecuritySpecEllipticCurve *) nil_chk(curve)) getField] isKindOfClass:[JavaSecuritySpecECFieldFp class]]) {
    c = new_LibOrgBouncycastleMathEcECCurve_Fp_initWithJavaMathBigInteger_withJavaMathBigInteger_withJavaMathBigInteger_([((JavaSecuritySpecECFieldFp *) nil_chk(((JavaSecuritySpecECFieldFp *) cast_chk([curve getField], [JavaSecuritySpecECFieldFp class])))) getP], [curve getA], [curve getB]);
  }
  else {
    IOSIntArray *k = [((JavaSecuritySpecECFieldF2m *) nil_chk(((JavaSecuritySpecECFieldF2m *) cast_chk([curve getField], [JavaSecuritySpecECFieldF2m class])))) getMidTermsOfReductionPolynomial];
    if (((IOSIntArray *) nil_chk(k))->size_ == 3) {
      c = new_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_([((JavaSecuritySpecECFieldF2m *) nil_chk(((JavaSecuritySpecECFieldF2m *) cast_chk([curve getField], [JavaSecuritySpecECFieldF2m class])))) getM], IOSIntArray_Get(k, 2), IOSIntArray_Get(k, 1), IOSIntArray_Get(k, 0), [curve getA], [curve getB]);
    }
    else {
      c = new_LibOrgBouncycastleMathEcECCurve_F2m_initWithInt_withInt_withJavaMathBigInteger_withJavaMathBigInteger_([((JavaSecuritySpecECFieldF2m *) nil_chk(((JavaSecuritySpecECFieldF2m *) cast_chk([curve getField], [JavaSecuritySpecECFieldF2m class])))) getM], IOSIntArray_Get(k, 0), [curve getA], [curve getB]);
    }
  }
  return LibOrgBouncycastleJcajceProviderAsymmetricUtilEC5Util_convertPointWithLibOrgBouncycastleMathEcECPoint_([c decodePointWithByteArray:encoded]);
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleJceECPointUtil)
