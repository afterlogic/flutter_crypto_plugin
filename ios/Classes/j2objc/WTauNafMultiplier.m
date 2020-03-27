//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/WTauNafMultiplier.java
//

#include "AbstractECMultiplier.h"
#include "ECCurve.h"
#include "ECFieldElement.h"
#include "ECPoint.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PreCompCallback.h"
#include "PreCompInfo.h"
#include "Tnaf.h"
#include "WTauNafMultiplier.h"
#include "WTauNafPreCompInfo.h"
#include "ZTauElement.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibOrgBouncycastleMathEcWTauNafMultiplier ()

- (LibOrgBouncycastleMathEcECPoint_AbstractF2m *)multiplyWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m:(LibOrgBouncycastleMathEcECPoint_AbstractF2m *)p
                                                                      withLibOrgBouncycastleMathEcZTauElement:(LibOrgBouncycastleMathEcZTauElement *)lambda
                                                                                                     withByte:(jbyte)a
                                                                                                     withByte:(jbyte)mu;

+ (LibOrgBouncycastleMathEcECPoint_AbstractF2m *)multiplyFromWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m:(LibOrgBouncycastleMathEcECPoint_AbstractF2m *)p
                                                                                                    withByteArray:(IOSByteArray *)u;

@end

__attribute__((unused)) static LibOrgBouncycastleMathEcECPoint_AbstractF2m *LibOrgBouncycastleMathEcWTauNafMultiplier_multiplyWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withLibOrgBouncycastleMathEcZTauElement_withByte_withByte_(LibOrgBouncycastleMathEcWTauNafMultiplier *self, LibOrgBouncycastleMathEcECPoint_AbstractF2m *p, LibOrgBouncycastleMathEcZTauElement *lambda, jbyte a, jbyte mu);

__attribute__((unused)) static LibOrgBouncycastleMathEcECPoint_AbstractF2m *LibOrgBouncycastleMathEcWTauNafMultiplier_multiplyFromWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByteArray_(LibOrgBouncycastleMathEcECPoint_AbstractF2m *p, IOSByteArray *u);

@interface LibOrgBouncycastleMathEcWTauNafMultiplier_1 : NSObject < LibOrgBouncycastleMathEcPreCompCallback > {
 @public
  LibOrgBouncycastleMathEcECPoint_AbstractF2m *val$p_;
  jbyte val$a_;
}

- (instancetype)initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m:(LibOrgBouncycastleMathEcECPoint_AbstractF2m *)capture$0
                                                           withByte:(jbyte)capture$1;

- (id<LibOrgBouncycastleMathEcPreCompInfo>)precomputeWithLibOrgBouncycastleMathEcPreCompInfo:(id<LibOrgBouncycastleMathEcPreCompInfo>)existing;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleMathEcWTauNafMultiplier_1)

__attribute__((unused)) static void LibOrgBouncycastleMathEcWTauNafMultiplier_1_initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_(LibOrgBouncycastleMathEcWTauNafMultiplier_1 *self, LibOrgBouncycastleMathEcECPoint_AbstractF2m *capture$0, jbyte capture$1);

__attribute__((unused)) static LibOrgBouncycastleMathEcWTauNafMultiplier_1 *new_LibOrgBouncycastleMathEcWTauNafMultiplier_1_initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_(LibOrgBouncycastleMathEcECPoint_AbstractF2m *capture$0, jbyte capture$1) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleMathEcWTauNafMultiplier_1 *create_LibOrgBouncycastleMathEcWTauNafMultiplier_1_initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_(LibOrgBouncycastleMathEcECPoint_AbstractF2m *capture$0, jbyte capture$1);

NSString *LibOrgBouncycastleMathEcWTauNafMultiplier_PRECOMP_NAME = @"bc_wtnaf";

@implementation LibOrgBouncycastleMathEcWTauNafMultiplier

+ (NSString *)PRECOMP_NAME {
  return LibOrgBouncycastleMathEcWTauNafMultiplier_PRECOMP_NAME;
}

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleMathEcWTauNafMultiplier_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (LibOrgBouncycastleMathEcECPoint *)multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)point
                                                                  withJavaMathBigInteger:(JavaMathBigInteger *)k {
  if (!([point isKindOfClass:[LibOrgBouncycastleMathEcECPoint_AbstractF2m class]])) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"Only ECPoint.AbstractF2m can be used in WTauNafMultiplier");
  }
  LibOrgBouncycastleMathEcECPoint_AbstractF2m *p = (LibOrgBouncycastleMathEcECPoint_AbstractF2m *) cast_chk(point, [LibOrgBouncycastleMathEcECPoint_AbstractF2m class]);
  LibOrgBouncycastleMathEcECCurve_AbstractF2m *curve = (LibOrgBouncycastleMathEcECCurve_AbstractF2m *) cast_chk([((LibOrgBouncycastleMathEcECPoint_AbstractF2m *) nil_chk(p)) getCurve], [LibOrgBouncycastleMathEcECCurve_AbstractF2m class]);
  jint m = [((LibOrgBouncycastleMathEcECCurve_AbstractF2m *) nil_chk(curve)) getFieldSize];
  jbyte a = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([curve getA])) toBigInteger])) charValue];
  jbyte mu = LibOrgBouncycastleMathEcTnaf_getMuWithInt_(a);
  IOSObjectArray *s = [curve getSi];
  LibOrgBouncycastleMathEcZTauElement *rho = LibOrgBouncycastleMathEcTnaf_partModReductionWithJavaMathBigInteger_withInt_withByte_withJavaMathBigIntegerArray_withByte_withByte_(k, m, a, s, mu, (jbyte) 10);
  return LibOrgBouncycastleMathEcWTauNafMultiplier_multiplyWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withLibOrgBouncycastleMathEcZTauElement_withByte_withByte_(self, p, rho, a, mu);
}

- (LibOrgBouncycastleMathEcECPoint_AbstractF2m *)multiplyWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m:(LibOrgBouncycastleMathEcECPoint_AbstractF2m *)p
                                                                      withLibOrgBouncycastleMathEcZTauElement:(LibOrgBouncycastleMathEcZTauElement *)lambda
                                                                                                     withByte:(jbyte)a
                                                                                                     withByte:(jbyte)mu {
  return LibOrgBouncycastleMathEcWTauNafMultiplier_multiplyWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withLibOrgBouncycastleMathEcZTauElement_withByte_withByte_(self, p, lambda, a, mu);
}

+ (LibOrgBouncycastleMathEcECPoint_AbstractF2m *)multiplyFromWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m:(LibOrgBouncycastleMathEcECPoint_AbstractF2m *)p
                                                                                                    withByteArray:(IOSByteArray *)u {
  return LibOrgBouncycastleMathEcWTauNafMultiplier_multiplyFromWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByteArray_(p, u);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x4, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint_AbstractF2m;", 0x2, 2, 3, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint_AbstractF2m;", 0xa, 4, 5, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(multiplyPositiveWithLibOrgBouncycastleMathEcECPoint:withJavaMathBigInteger:);
  methods[2].selector = @selector(multiplyWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m:withLibOrgBouncycastleMathEcZTauElement:withByte:withByte:);
  methods[3].selector = @selector(multiplyFromWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "PRECOMP_NAME", "LNSString;", .constantValue.asLong = 0, 0x18, -1, 6, -1, -1 },
  };
  static const void *ptrTable[] = { "multiplyPositive", "LLibOrgBouncycastleMathEcECPoint;LJavaMathBigInteger;", "multiplyWTnaf", "LLibOrgBouncycastleMathEcECPoint_AbstractF2m;LLibOrgBouncycastleMathEcZTauElement;BB", "multiplyFromWTnaf", "LLibOrgBouncycastleMathEcECPoint_AbstractF2m;[B", &LibOrgBouncycastleMathEcWTauNafMultiplier_PRECOMP_NAME };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcWTauNafMultiplier = { "WTauNafMultiplier", "lib.org.bouncycastle.math.ec", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcWTauNafMultiplier;
}

@end

void LibOrgBouncycastleMathEcWTauNafMultiplier_init(LibOrgBouncycastleMathEcWTauNafMultiplier *self) {
  LibOrgBouncycastleMathEcAbstractECMultiplier_init(self);
}

LibOrgBouncycastleMathEcWTauNafMultiplier *new_LibOrgBouncycastleMathEcWTauNafMultiplier_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcWTauNafMultiplier, init)
}

LibOrgBouncycastleMathEcWTauNafMultiplier *create_LibOrgBouncycastleMathEcWTauNafMultiplier_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcWTauNafMultiplier, init)
}

LibOrgBouncycastleMathEcECPoint_AbstractF2m *LibOrgBouncycastleMathEcWTauNafMultiplier_multiplyWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withLibOrgBouncycastleMathEcZTauElement_withByte_withByte_(LibOrgBouncycastleMathEcWTauNafMultiplier *self, LibOrgBouncycastleMathEcECPoint_AbstractF2m *p, LibOrgBouncycastleMathEcZTauElement *lambda, jbyte a, jbyte mu) {
  IOSObjectArray *alpha = (a == 0) ? JreLoadStatic(LibOrgBouncycastleMathEcTnaf, alpha0) : JreLoadStatic(LibOrgBouncycastleMathEcTnaf, alpha1);
  JavaMathBigInteger *tw = LibOrgBouncycastleMathEcTnaf_getTwWithByte_withInt_(mu, LibOrgBouncycastleMathEcTnaf_WIDTH);
  IOSByteArray *u = LibOrgBouncycastleMathEcTnaf_tauAdicWNafWithByte_withLibOrgBouncycastleMathEcZTauElement_withByte_withJavaMathBigInteger_withJavaMathBigInteger_withLibOrgBouncycastleMathEcZTauElementArray_(mu, lambda, LibOrgBouncycastleMathEcTnaf_WIDTH, JavaMathBigInteger_valueOfWithLong_(LibOrgBouncycastleMathEcTnaf_POW_2_WIDTH), tw, alpha);
  return LibOrgBouncycastleMathEcWTauNafMultiplier_multiplyFromWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByteArray_(p, u);
}

LibOrgBouncycastleMathEcECPoint_AbstractF2m *LibOrgBouncycastleMathEcWTauNafMultiplier_multiplyFromWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByteArray_(LibOrgBouncycastleMathEcECPoint_AbstractF2m *p, IOSByteArray *u) {
  LibOrgBouncycastleMathEcWTauNafMultiplier_initialize();
  LibOrgBouncycastleMathEcECCurve_AbstractF2m *curve = (LibOrgBouncycastleMathEcECCurve_AbstractF2m *) cast_chk([((LibOrgBouncycastleMathEcECPoint_AbstractF2m *) nil_chk(p)) getCurve], [LibOrgBouncycastleMathEcECCurve_AbstractF2m class]);
  jbyte a = [((JavaMathBigInteger *) nil_chk([((LibOrgBouncycastleMathEcECFieldElement *) nil_chk([((LibOrgBouncycastleMathEcECCurve_AbstractF2m *) nil_chk(curve)) getA])) toBigInteger])) charValue];
  LibOrgBouncycastleMathEcWTauNafPreCompInfo *preCompInfo = (LibOrgBouncycastleMathEcWTauNafPreCompInfo *) cast_chk([curve precomputeWithLibOrgBouncycastleMathEcECPoint:p withNSString:LibOrgBouncycastleMathEcWTauNafMultiplier_PRECOMP_NAME withLibOrgBouncycastleMathEcPreCompCallback:new_LibOrgBouncycastleMathEcWTauNafMultiplier_1_initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_(p, a)], [LibOrgBouncycastleMathEcWTauNafPreCompInfo class]);
  IOSObjectArray *pu = [((LibOrgBouncycastleMathEcWTauNafPreCompInfo *) nil_chk(preCompInfo)) getPreComp];
  IOSObjectArray *puNeg = [IOSObjectArray newArrayWithLength:((IOSObjectArray *) nil_chk(pu))->size_ type:LibOrgBouncycastleMathEcECPoint_AbstractF2m_class_()];
  for (jint i = 0; i < pu->size_; ++i) {
    (void) IOSObjectArray_Set(puNeg, i, (LibOrgBouncycastleMathEcECPoint_AbstractF2m *) cast_chk([((LibOrgBouncycastleMathEcECPoint_AbstractF2m *) nil_chk(IOSObjectArray_Get(pu, i))) negate], [LibOrgBouncycastleMathEcECPoint_AbstractF2m class]));
  }
  LibOrgBouncycastleMathEcECPoint_AbstractF2m *q = (LibOrgBouncycastleMathEcECPoint_AbstractF2m *) cast_chk([((LibOrgBouncycastleMathEcECCurve *) nil_chk([p getCurve])) getInfinity], [LibOrgBouncycastleMathEcECPoint_AbstractF2m class]);
  jint tauCount = 0;
  for (jint i = ((IOSByteArray *) nil_chk(u))->size_ - 1; i >= 0; i--) {
    ++tauCount;
    jint ui = IOSByteArray_Get(u, i);
    if (ui != 0) {
      q = [((LibOrgBouncycastleMathEcECPoint_AbstractF2m *) nil_chk(q)) tauPowWithInt:tauCount];
      tauCount = 0;
      LibOrgBouncycastleMathEcECPoint *x = ui > 0 ? IOSObjectArray_Get(pu, JreURShift32(ui, 1)) : IOSObjectArray_Get(puNeg, JreURShift32((-ui), 1));
      q = (LibOrgBouncycastleMathEcECPoint_AbstractF2m *) cast_chk([((LibOrgBouncycastleMathEcECPoint_AbstractF2m *) nil_chk(q)) addWithLibOrgBouncycastleMathEcECPoint:x], [LibOrgBouncycastleMathEcECPoint_AbstractF2m class]);
    }
  }
  if (tauCount > 0) {
    q = [((LibOrgBouncycastleMathEcECPoint_AbstractF2m *) nil_chk(q)) tauPowWithInt:tauCount];
  }
  return q;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcWTauNafMultiplier)

@implementation LibOrgBouncycastleMathEcWTauNafMultiplier_1

- (instancetype)initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m:(LibOrgBouncycastleMathEcECPoint_AbstractF2m *)capture$0
                                                           withByte:(jbyte)capture$1 {
  LibOrgBouncycastleMathEcWTauNafMultiplier_1_initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_(self, capture$0, capture$1);
  return self;
}

- (id<LibOrgBouncycastleMathEcPreCompInfo>)precomputeWithLibOrgBouncycastleMathEcPreCompInfo:(id<LibOrgBouncycastleMathEcPreCompInfo>)existing {
  if ([existing isKindOfClass:[LibOrgBouncycastleMathEcWTauNafPreCompInfo class]]) {
    return existing;
  }
  LibOrgBouncycastleMathEcWTauNafPreCompInfo *result = new_LibOrgBouncycastleMathEcWTauNafPreCompInfo_init();
  [result setPreCompWithLibOrgBouncycastleMathEcECPoint_AbstractF2mArray:LibOrgBouncycastleMathEcTnaf_getPreCompWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_(val$p_, val$a_)];
  return result;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcPreCompInfo;", 0x1, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m:withByte:);
  methods[1].selector = @selector(precomputeWithLibOrgBouncycastleMathEcPreCompInfo:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "val$p_", "LLibOrgBouncycastleMathEcECPoint_AbstractF2m;", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
    { "val$a_", "B", .constantValue.asLong = 0, 0x1012, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "precompute", "LLibOrgBouncycastleMathEcPreCompInfo;", "LLibOrgBouncycastleMathEcWTauNafMultiplier;", "multiplyFromWTnafWithLibOrgBouncycastleMathEcECPoint_AbstractF2m:withByteArray:" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcWTauNafMultiplier_1 = { "", "lib.org.bouncycastle.math.ec", ptrTable, methods, fields, 7, 0x8018, 2, 2, 2, -1, 3, -1, -1 };
  return &_LibOrgBouncycastleMathEcWTauNafMultiplier_1;
}

@end

void LibOrgBouncycastleMathEcWTauNafMultiplier_1_initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_(LibOrgBouncycastleMathEcWTauNafMultiplier_1 *self, LibOrgBouncycastleMathEcECPoint_AbstractF2m *capture$0, jbyte capture$1) {
  self->val$p_ = capture$0;
  self->val$a_ = capture$1;
  NSObject_init(self);
}

LibOrgBouncycastleMathEcWTauNafMultiplier_1 *new_LibOrgBouncycastleMathEcWTauNafMultiplier_1_initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_(LibOrgBouncycastleMathEcECPoint_AbstractF2m *capture$0, jbyte capture$1) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcWTauNafMultiplier_1, initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_, capture$0, capture$1)
}

LibOrgBouncycastleMathEcWTauNafMultiplier_1 *create_LibOrgBouncycastleMathEcWTauNafMultiplier_1_initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_(LibOrgBouncycastleMathEcECPoint_AbstractF2m *capture$0, jbyte capture$1) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcWTauNafMultiplier_1, initWithLibOrgBouncycastleMathEcECPoint_AbstractF2m_withByte_, capture$0, capture$1)
}
