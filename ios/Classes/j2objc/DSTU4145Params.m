//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ua/DSTU4145Params.java
//

#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1OctetString.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "Arrays.h"
#include "DEROctetString.h"
#include "DERSequence.h"
#include "DSTU4145ECBinary.h"
#include "DSTU4145Params.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/IllegalArgumentException.h"

@interface LibOrgBouncycastleAsn1UaDSTU4145Params () {
 @public
  LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurve_;
  LibOrgBouncycastleAsn1UaDSTU4145ECBinary *ecbinary_;
  IOSByteArray *dke_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1UaDSTU4145Params, namedCurve_, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1UaDSTU4145Params, ecbinary_, LibOrgBouncycastleAsn1UaDSTU4145ECBinary *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1UaDSTU4145Params, dke_, IOSByteArray *)

inline IOSByteArray *LibOrgBouncycastleAsn1UaDSTU4145Params_get_DEFAULT_DKE(void);
static IOSByteArray *LibOrgBouncycastleAsn1UaDSTU4145Params_DEFAULT_DKE;
J2OBJC_STATIC_FIELD_OBJ_FINAL(LibOrgBouncycastleAsn1UaDSTU4145Params, DEFAULT_DKE, IOSByteArray *)

J2OBJC_INITIALIZED_DEFN(LibOrgBouncycastleAsn1UaDSTU4145Params)

@implementation LibOrgBouncycastleAsn1UaDSTU4145Params

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)namedCurve {
  LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(self, namedCurve);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)namedCurve
                                                     withByteArray:(IOSByteArray *)dke {
  LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(self, namedCurve, dke);
  return self;
}

- (instancetype)initWithLibOrgBouncycastleAsn1UaDSTU4145ECBinary:(LibOrgBouncycastleAsn1UaDSTU4145ECBinary *)ecbinary {
  LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1UaDSTU4145ECBinary_(self, ecbinary);
  return self;
}

- (jboolean)isNamedCurve {
  return namedCurve_ != nil;
}

- (LibOrgBouncycastleAsn1UaDSTU4145ECBinary *)getECBinary {
  return ecbinary_;
}

- (IOSByteArray *)getDKE {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(dke_);
}

+ (IOSByteArray *)getDefaultDKE {
  return LibOrgBouncycastleAsn1UaDSTU4145Params_getDefaultDKE();
}

- (LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)getNamedCurve {
  return namedCurve_;
}

+ (LibOrgBouncycastleAsn1UaDSTU4145Params *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1UaDSTU4145Params_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
  if (namedCurve_ != nil) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:namedCurve_];
  }
  else {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:ecbinary_];
  }
  if (!LibOrgBouncycastleUtilArrays_areEqualWithByteArray_withByteArray_(dke_, LibOrgBouncycastleAsn1UaDSTU4145Params_DEFAULT_DKE)) {
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(dke_)];
  }
  return new_LibOrgBouncycastleAsn1DERSequence_initWithLibOrgBouncycastleAsn1ASN1EncodableVector_(v);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1UaDSTU4145ECBinary;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1UaDSTU4145Params;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:);
  methods[1].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withByteArray:);
  methods[2].selector = @selector(initWithLibOrgBouncycastleAsn1UaDSTU4145ECBinary:);
  methods[3].selector = @selector(isNamedCurve);
  methods[4].selector = @selector(getECBinary);
  methods[5].selector = @selector(getDKE);
  methods[6].selector = @selector(getDefaultDKE);
  methods[7].selector = @selector(getNamedCurve);
  methods[8].selector = @selector(getInstanceWithId:);
  methods[9].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "DEFAULT_DKE", "[B", .constantValue.asLong = 0, 0x1a, -1, 5, -1, -1 },
    { "namedCurve_", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ecbinary_", "LLibOrgBouncycastleAsn1UaDSTU4145ECBinary;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "dke_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;[B", "LLibOrgBouncycastleAsn1UaDSTU4145ECBinary;", "getInstance", "LNSObject;", &LibOrgBouncycastleAsn1UaDSTU4145Params_DEFAULT_DKE };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1UaDSTU4145Params = { "DSTU4145Params", "lib.org.bouncycastle.asn1.ua", ptrTable, methods, fields, 7, 0x1, 10, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1UaDSTU4145Params;
}

+ (void)initialize {
  if (self == [LibOrgBouncycastleAsn1UaDSTU4145Params class]) {
    LibOrgBouncycastleAsn1UaDSTU4145Params_DEFAULT_DKE = [IOSByteArray newArrayWithBytes:(jbyte[]){ (jbyte) (jint) 0xa9, (jbyte) (jint) 0xd6, (jbyte) (jint) 0xeb, (jint) 0x45, (jbyte) (jint) 0xf1, (jint) 0x3c, (jint) 0x70, (jbyte) (jint) 0x82, (jbyte) (jint) 0x80, (jbyte) (jint) 0xc4, (jbyte) (jint) 0x96, (jint) 0x7b, (jint) 0x23, (jint) 0x1f, (jint) 0x5e, (jbyte) (jint) 0xad, (jbyte) (jint) 0xf6, (jint) 0x58, (jbyte) (jint) 0xeb, (jbyte) (jint) 0xa4, (jbyte) (jint) 0xc0, (jint) 0x37, (jint) 0x29, (jint) 0x1d, (jint) 0x38, (jbyte) (jint) 0xd9, (jint) 0x6b, (jbyte) (jint) 0xf0, (jint) 0x25, (jbyte) (jint) 0xca, (jint) 0x4e, (jint) 0x17, (jbyte) (jint) 0xf8, (jbyte) (jint) 0xe9, (jint) 0x72, (jint) 0x0d, (jbyte) (jint) 0xc6, (jint) 0x15, (jbyte) (jint) 0xb4, (jint) 0x3a, (jint) 0x28, (jbyte) (jint) 0x97, (jint) 0x5f, (jint) 0x0b, (jbyte) (jint) 0xc1, (jbyte) (jint) 0xde, (jbyte) (jint) 0xa3, (jint) 0x64, (jint) 0x38, (jbyte) (jint) 0xb5, (jint) 0x64, (jbyte) (jint) 0xea, (jint) 0x2c, (jint) 0x17, (jbyte) (jint) 0x9f, (jbyte) (jint) 0xd0, (jint) 0x12, (jint) 0x3e, (jint) 0x6d, (jbyte) (jint) 0xb8, (jbyte) (jint) 0xfa, (jbyte) (jint) 0xc5, (jint) 0x79, (jint) 0x04 } count:64];
    J2OBJC_SET_INITIALIZED(LibOrgBouncycastleAsn1UaDSTU4145Params)
  }
}

@end

void LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1UaDSTU4145Params *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurve) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->dke_ = LibOrgBouncycastleAsn1UaDSTU4145Params_DEFAULT_DKE;
  self->namedCurve_ = namedCurve;
}

LibOrgBouncycastleAsn1UaDSTU4145Params *new_LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurve) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1UaDSTU4145Params, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, namedCurve)
}

LibOrgBouncycastleAsn1UaDSTU4145Params *create_LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurve) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1UaDSTU4145Params, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_, namedCurve)
}

void LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(LibOrgBouncycastleAsn1UaDSTU4145Params *self, LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurve, IOSByteArray *dke) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->dke_ = LibOrgBouncycastleAsn1UaDSTU4145Params_DEFAULT_DKE;
  self->namedCurve_ = namedCurve;
  self->dke_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(dke);
}

LibOrgBouncycastleAsn1UaDSTU4145Params *new_LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurve, IOSByteArray *dke) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1UaDSTU4145Params, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_, namedCurve, dke)
}

LibOrgBouncycastleAsn1UaDSTU4145Params *create_LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *namedCurve, IOSByteArray *dke) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1UaDSTU4145Params, initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_withByteArray_, namedCurve, dke)
}

void LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1UaDSTU4145ECBinary_(LibOrgBouncycastleAsn1UaDSTU4145Params *self, LibOrgBouncycastleAsn1UaDSTU4145ECBinary *ecbinary) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->dke_ = LibOrgBouncycastleAsn1UaDSTU4145Params_DEFAULT_DKE;
  self->ecbinary_ = ecbinary;
}

LibOrgBouncycastleAsn1UaDSTU4145Params *new_LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1UaDSTU4145ECBinary_(LibOrgBouncycastleAsn1UaDSTU4145ECBinary *ecbinary) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1UaDSTU4145Params, initWithLibOrgBouncycastleAsn1UaDSTU4145ECBinary_, ecbinary)
}

LibOrgBouncycastleAsn1UaDSTU4145Params *create_LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1UaDSTU4145ECBinary_(LibOrgBouncycastleAsn1UaDSTU4145ECBinary *ecbinary) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1UaDSTU4145Params, initWithLibOrgBouncycastleAsn1UaDSTU4145ECBinary_, ecbinary)
}

IOSByteArray *LibOrgBouncycastleAsn1UaDSTU4145Params_getDefaultDKE() {
  LibOrgBouncycastleAsn1UaDSTU4145Params_initialize();
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(LibOrgBouncycastleAsn1UaDSTU4145Params_DEFAULT_DKE);
}

LibOrgBouncycastleAsn1UaDSTU4145Params *LibOrgBouncycastleAsn1UaDSTU4145Params_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1UaDSTU4145Params_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1UaDSTU4145Params class]]) {
    return (LibOrgBouncycastleAsn1UaDSTU4145Params *) obj;
  }
  if (obj != nil) {
    LibOrgBouncycastleAsn1ASN1Sequence *seq = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_(obj);
    LibOrgBouncycastleAsn1UaDSTU4145Params *params;
    if ([[((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0] isKindOfClass:[LibOrgBouncycastleAsn1ASN1ObjectIdentifier class]]) {
      params = new_LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier_(LibOrgBouncycastleAsn1ASN1ObjectIdentifier_getInstanceWithId_([seq getObjectAtWithInt:0]));
    }
    else {
      params = new_LibOrgBouncycastleAsn1UaDSTU4145Params_initWithLibOrgBouncycastleAsn1UaDSTU4145ECBinary_(LibOrgBouncycastleAsn1UaDSTU4145ECBinary_getInstanceWithId_([seq getObjectAtWithInt:0]));
    }
    if ([seq size] == 2) {
      params->dke_ = [((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(LibOrgBouncycastleAsn1ASN1OctetString_getInstanceWithId_([seq getObjectAtWithInt:1]))) getOctets];
      if (((IOSByteArray *) nil_chk(params->dke_))->size_ != ((IOSByteArray *) nil_chk(LibOrgBouncycastleAsn1UaDSTU4145Params_DEFAULT_DKE))->size_) {
        @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"object parse error");
      }
    }
    return params;
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(@"object parse error");
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1UaDSTU4145Params)
