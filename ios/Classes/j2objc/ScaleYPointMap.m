//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/math/ec/ScaleYPointMap.java
//

#include "ECFieldElement.h"
#include "ECPoint.h"
#include "J2ObjC_source.h"
#include "ScaleYPointMap.h"

@implementation LibOrgBouncycastleMathEcScaleYPointMap

- (instancetype)initWithLibOrgBouncycastleMathEcECFieldElement:(LibOrgBouncycastleMathEcECFieldElement *)scale_ {
  LibOrgBouncycastleMathEcScaleYPointMap_initWithLibOrgBouncycastleMathEcECFieldElement_(self, scale_);
  return self;
}

- (LibOrgBouncycastleMathEcECPoint *)mapWithLibOrgBouncycastleMathEcECPoint:(LibOrgBouncycastleMathEcECPoint *)p {
  return [((LibOrgBouncycastleMathEcECPoint *) nil_chk(p)) scaleYWithLibOrgBouncycastleMathEcECFieldElement:scale__];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleMathEcECPoint;", 0x1, 1, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleMathEcECFieldElement:);
  methods[1].selector = @selector(mapWithLibOrgBouncycastleMathEcECPoint:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "scale__", "LLibOrgBouncycastleMathEcECFieldElement;", .constantValue.asLong = 0, 0x14, 3, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleMathEcECFieldElement;", "map", "LLibOrgBouncycastleMathEcECPoint;", "scale" };
  static const J2ObjcClassInfo _LibOrgBouncycastleMathEcScaleYPointMap = { "ScaleYPointMap", "lib.org.bouncycastle.math.ec", ptrTable, methods, fields, 7, 0x1, 2, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleMathEcScaleYPointMap;
}

@end

void LibOrgBouncycastleMathEcScaleYPointMap_initWithLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcScaleYPointMap *self, LibOrgBouncycastleMathEcECFieldElement *scale_) {
  NSObject_init(self);
  self->scale__ = scale_;
}

LibOrgBouncycastleMathEcScaleYPointMap *new_LibOrgBouncycastleMathEcScaleYPointMap_initWithLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcECFieldElement *scale_) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleMathEcScaleYPointMap, initWithLibOrgBouncycastleMathEcECFieldElement_, scale_)
}

LibOrgBouncycastleMathEcScaleYPointMap *create_LibOrgBouncycastleMathEcScaleYPointMap_initWithLibOrgBouncycastleMathEcECFieldElement_(LibOrgBouncycastleMathEcECFieldElement *scale_) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleMathEcScaleYPointMap, initWithLibOrgBouncycastleMathEcECFieldElement_, scale_)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleMathEcScaleYPointMap)