//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/rainbow/RainbowPrivateKeyParameters.java
//

#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "RainbowKeyParameters.h"
#include "RainbowPrivateKeyParameters.h"

@interface LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters () {
 @public
  IOSObjectArray *A1inv_;
  IOSShortArray *b1_;
  IOSObjectArray *A2inv_;
  IOSShortArray *b2_;
  IOSIntArray *vi_;
  IOSObjectArray *layers_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters, A1inv_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters, b1_, IOSShortArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters, A2inv_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters, b2_, IOSShortArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters, vi_, IOSIntArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters, layers_, IOSObjectArray *)

@implementation LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters

- (instancetype)initWithShortArray2:(IOSObjectArray *)A1inv
                     withShortArray:(IOSShortArray *)b1
                    withShortArray2:(IOSObjectArray *)A2inv
                     withShortArray:(IOSShortArray *)b2
                       withIntArray:(IOSIntArray *)vi
withLibOrgBouncycastlePqcCryptoRainbowLayerArray:(IOSObjectArray *)layers {
  LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters_initWithShortArray2_withShortArray_withShortArray2_withShortArray_withIntArray_withLibOrgBouncycastlePqcCryptoRainbowLayerArray_(self, A1inv, b1, A2inv, b2, vi, layers);
  return self;
}

- (IOSShortArray *)getB1 {
  return self->b1_;
}

- (IOSObjectArray *)getInvA1 {
  return self->A1inv_;
}

- (IOSShortArray *)getB2 {
  return self->b2_;
}

- (IOSObjectArray *)getInvA2 {
  return self->A2inv_;
}

- (IOSObjectArray *)getLayers {
  return self->layers_;
}

- (IOSIntArray *)getVi {
  return vi_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "[S", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[[S", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[S", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[[S", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibOrgBouncycastlePqcCryptoRainbowLayer;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[I", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithShortArray2:withShortArray:withShortArray2:withShortArray:withIntArray:withLibOrgBouncycastlePqcCryptoRainbowLayerArray:);
  methods[1].selector = @selector(getB1);
  methods[2].selector = @selector(getInvA1);
  methods[3].selector = @selector(getB2);
  methods[4].selector = @selector(getInvA2);
  methods[5].selector = @selector(getLayers);
  methods[6].selector = @selector(getVi);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "A1inv_", "[[S", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "b1_", "[S", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "A2inv_", "[[S", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "b2_", "[S", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "vi_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "layers_", "[LLibOrgBouncycastlePqcCryptoRainbowLayer;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[[S[S[[S[S[I[LLibOrgBouncycastlePqcCryptoRainbowLayer;" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters = { "RainbowPrivateKeyParameters", "lib.org.bouncycastle.pqc.crypto.rainbow", ptrTable, methods, fields, 7, 0x1, 7, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters;
}

@end

void LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters_initWithShortArray2_withShortArray_withShortArray2_withShortArray_withIntArray_withLibOrgBouncycastlePqcCryptoRainbowLayerArray_(LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters *self, IOSObjectArray *A1inv, IOSShortArray *b1, IOSObjectArray *A2inv, IOSShortArray *b2, IOSIntArray *vi, IOSObjectArray *layers) {
  LibOrgBouncycastlePqcCryptoRainbowRainbowKeyParameters_initWithBoolean_withInt_(self, true, IOSIntArray_Get(vi, ((IOSIntArray *) nil_chk(vi))->size_ - 1) - IOSIntArray_Get(vi, 0));
  self->A1inv_ = A1inv;
  self->b1_ = b1;
  self->A2inv_ = A2inv;
  self->b2_ = b2;
  self->vi_ = vi;
  self->layers_ = layers;
}

LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters *new_LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters_initWithShortArray2_withShortArray_withShortArray2_withShortArray_withIntArray_withLibOrgBouncycastlePqcCryptoRainbowLayerArray_(IOSObjectArray *A1inv, IOSShortArray *b1, IOSObjectArray *A2inv, IOSShortArray *b2, IOSIntArray *vi, IOSObjectArray *layers) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters, initWithShortArray2_withShortArray_withShortArray2_withShortArray_withIntArray_withLibOrgBouncycastlePqcCryptoRainbowLayerArray_, A1inv, b1, A2inv, b2, vi, layers)
}

LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters *create_LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters_initWithShortArray2_withShortArray_withShortArray2_withShortArray_withIntArray_withLibOrgBouncycastlePqcCryptoRainbowLayerArray_(IOSObjectArray *A1inv, IOSShortArray *b1, IOSObjectArray *A2inv, IOSShortArray *b2, IOSIntArray *vi, IOSObjectArray *layers) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters, initWithShortArray2_withShortArray_withShortArray2_withShortArray_withIntArray_withLibOrgBouncycastlePqcCryptoRainbowLayerArray_, A1inv, b1, A2inv, b2, vi, layers)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoRainbowRainbowPrivateKeyParameters)
