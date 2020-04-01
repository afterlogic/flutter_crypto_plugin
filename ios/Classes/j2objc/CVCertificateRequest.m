//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/eac/CVCertificateRequest.java
//

#include "ASN1ApplicationSpecific.h"
#include "ASN1Encodable.h"
#include "ASN1EncodableVector.h"
#include "ASN1Object.h"
#include "ASN1ParsingException.h"
#include "ASN1Primitive.h"
#include "ASN1Sequence.h"
#include "Arrays.h"
#include "BERTags.h"
#include "CVCertificateRequest.h"
#include "CertificateBody.h"
#include "DERApplicationSpecific.h"
#include "DEROctetString.h"
#include "EACTags.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "PublicKeyDataObject.h"
#include "java/io/IOException.h"
#include "java/lang/IllegalStateException.h"
#include "java/util/Enumeration.h"

@interface LibOrgBouncycastleAsn1EacCVCertificateRequest () {
 @public
  LibOrgBouncycastleAsn1ASN1ApplicationSpecific *original_;
  LibOrgBouncycastleAsn1EacCertificateBody *certificateBody_;
  IOSByteArray *innerSignature_;
  IOSByteArray *outerSignature_;
}

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)request;

- (void)initCertBodyWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)request OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EacCVCertificateRequest, original_, LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EacCVCertificateRequest, certificateBody_, LibOrgBouncycastleAsn1EacCertificateBody *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EacCVCertificateRequest, innerSignature_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleAsn1EacCVCertificateRequest, outerSignature_, IOSByteArray *)

inline jint LibOrgBouncycastleAsn1EacCVCertificateRequest_get_bodyValid(void);
#define LibOrgBouncycastleAsn1EacCVCertificateRequest_bodyValid 1
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1EacCVCertificateRequest, bodyValid, jint)

inline jint LibOrgBouncycastleAsn1EacCVCertificateRequest_get_signValid(void);
#define LibOrgBouncycastleAsn1EacCVCertificateRequest_signValid 2
J2OBJC_STATIC_FIELD_CONSTANT(LibOrgBouncycastleAsn1EacCVCertificateRequest, signValid, jint)

__attribute__((unused)) static void LibOrgBouncycastleAsn1EacCVCertificateRequest_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1EacCVCertificateRequest *self, LibOrgBouncycastleAsn1ASN1ApplicationSpecific *request);

__attribute__((unused)) static LibOrgBouncycastleAsn1EacCVCertificateRequest *new_LibOrgBouncycastleAsn1EacCVCertificateRequest_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *request) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleAsn1EacCVCertificateRequest *create_LibOrgBouncycastleAsn1EacCVCertificateRequest_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *request);

__attribute__((unused)) static void LibOrgBouncycastleAsn1EacCVCertificateRequest_initCertBodyWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1EacCVCertificateRequest *self, LibOrgBouncycastleAsn1ASN1ApplicationSpecific *request);

@implementation LibOrgBouncycastleAsn1EacCVCertificateRequest

- (instancetype)initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)request {
  LibOrgBouncycastleAsn1EacCVCertificateRequest_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(self, request);
  return self;
}

- (void)initCertBodyWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *)request {
  LibOrgBouncycastleAsn1EacCVCertificateRequest_initCertBodyWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(self, request);
}

+ (LibOrgBouncycastleAsn1EacCVCertificateRequest *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1EacCVCertificateRequest_getInstanceWithId_(obj);
}

- (LibOrgBouncycastleAsn1EacCertificateBody *)getCertificateBody {
  return certificateBody_;
}

- (LibOrgBouncycastleAsn1EacPublicKeyDataObject *)getPublicKey {
  return [((LibOrgBouncycastleAsn1EacCertificateBody *) nil_chk(certificateBody_)) getPublicKey];
}

- (IOSByteArray *)getInnerSignature {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(innerSignature_);
}

- (IOSByteArray *)getOuterSignature {
  return LibOrgBouncycastleUtilArrays_cloneWithByteArray_(outerSignature_);
}

- (jboolean)hasOuterSignature {
  return outerSignature_ != nil;
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toASN1Primitive {
  if (original_ != nil) {
    return original_;
  }
  else {
    LibOrgBouncycastleAsn1ASN1EncodableVector *v = new_LibOrgBouncycastleAsn1ASN1EncodableVector_init();
    [v addWithLibOrgBouncycastleAsn1ASN1Encodable:certificateBody_];
    @try {
      [v addWithLibOrgBouncycastleAsn1ASN1Encodable:new_LibOrgBouncycastleAsn1DERApplicationSpecific_initWithBoolean_withInt_withLibOrgBouncycastleAsn1ASN1Encodable_(false, LibOrgBouncycastleAsn1EacEACTags_STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, new_LibOrgBouncycastleAsn1DEROctetString_initWithByteArray_(innerSignature_))];
    }
    @catch (JavaIoIOException *e) {
      @throw new_JavaLangIllegalStateException_initWithNSString_(@"unable to convert signature!");
    }
    return new_LibOrgBouncycastleAsn1DERApplicationSpecific_initWithInt_withLibOrgBouncycastleAsn1ASN1EncodableVector_(LibOrgBouncycastleAsn1EacEACTags_CARDHOLDER_CERTIFICATE, v);
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, 0, 1, -1, -1, -1 },
    { NULL, "V", 0x2, 2, 0, 1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacCVCertificateRequest;", 0x9, 3, 4, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacCertificateBody;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1EacPublicKeyDataObject;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:);
  methods[1].selector = @selector(initCertBodyWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific:);
  methods[2].selector = @selector(getInstanceWithId:);
  methods[3].selector = @selector(getCertificateBody);
  methods[4].selector = @selector(getPublicKey);
  methods[5].selector = @selector(getInnerSignature);
  methods[6].selector = @selector(getOuterSignature);
  methods[7].selector = @selector(hasOuterSignature);
  methods[8].selector = @selector(toASN1Primitive);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "original_", "LLibOrgBouncycastleAsn1ASN1ApplicationSpecific;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "certificateBody_", "LLibOrgBouncycastleAsn1EacCertificateBody;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "innerSignature_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "outerSignature_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "bodyValid", "I", .constantValue.asInt = LibOrgBouncycastleAsn1EacCVCertificateRequest_bodyValid, 0x1a, -1, -1, -1, -1 },
    { "signValid", "I", .constantValue.asInt = LibOrgBouncycastleAsn1EacCVCertificateRequest_signValid, 0x1a, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleAsn1ASN1ApplicationSpecific;", "LJavaIoIOException;", "initCertBody", "getInstance", "LNSObject;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1EacCVCertificateRequest = { "CVCertificateRequest", "lib.org.bouncycastle.asn1.eac", ptrTable, methods, fields, 7, 0x1, 9, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1EacCVCertificateRequest;
}

@end

void LibOrgBouncycastleAsn1EacCVCertificateRequest_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1EacCVCertificateRequest *self, LibOrgBouncycastleAsn1ASN1ApplicationSpecific *request) {
  LibOrgBouncycastleAsn1ASN1Object_init(self);
  self->innerSignature_ = nil;
  self->outerSignature_ = nil;
  self->original_ = request;
  if ([((LibOrgBouncycastleAsn1ASN1ApplicationSpecific *) nil_chk(request)) isConstructed] && [request getApplicationTag] == LibOrgBouncycastleAsn1EacEACTags_AUTHENTIFICATION_DATA) {
    LibOrgBouncycastleAsn1ASN1Sequence *seq = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([request getObjectWithInt:LibOrgBouncycastleAsn1BERTags_SEQUENCE]);
    LibOrgBouncycastleAsn1EacCVCertificateRequest_initCertBodyWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(self, LibOrgBouncycastleAsn1ASN1ApplicationSpecific_getInstanceWithId_([((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjectAtWithInt:0]));
    self->outerSignature_ = [((LibOrgBouncycastleAsn1ASN1ApplicationSpecific *) nil_chk(LibOrgBouncycastleAsn1ASN1ApplicationSpecific_getInstanceWithId_([seq getObjectAtWithInt:[seq size] - 1]))) getContents];
  }
  else {
    LibOrgBouncycastleAsn1EacCVCertificateRequest_initCertBodyWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(self, request);
  }
}

LibOrgBouncycastleAsn1EacCVCertificateRequest *new_LibOrgBouncycastleAsn1EacCVCertificateRequest_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *request) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1EacCVCertificateRequest, initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_, request)
}

LibOrgBouncycastleAsn1EacCVCertificateRequest *create_LibOrgBouncycastleAsn1EacCVCertificateRequest_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific *request) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1EacCVCertificateRequest, initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_, request)
}

void LibOrgBouncycastleAsn1EacCVCertificateRequest_initCertBodyWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1EacCVCertificateRequest *self, LibOrgBouncycastleAsn1ASN1ApplicationSpecific *request) {
  if ([((LibOrgBouncycastleAsn1ASN1ApplicationSpecific *) nil_chk(request)) getApplicationTag] == LibOrgBouncycastleAsn1EacEACTags_CARDHOLDER_CERTIFICATE) {
    jint valid = 0;
    LibOrgBouncycastleAsn1ASN1Sequence *seq = LibOrgBouncycastleAsn1ASN1Sequence_getInstanceWithId_([request getObjectWithInt:LibOrgBouncycastleAsn1BERTags_SEQUENCE]);
    for (id<JavaUtilEnumeration> en = [((LibOrgBouncycastleAsn1ASN1Sequence *) nil_chk(seq)) getObjects]; [((id<JavaUtilEnumeration>) nil_chk(en)) hasMoreElements]; ) {
      LibOrgBouncycastleAsn1ASN1ApplicationSpecific *obj = LibOrgBouncycastleAsn1ASN1ApplicationSpecific_getInstanceWithId_([en nextElement]);
      switch ([((LibOrgBouncycastleAsn1ASN1ApplicationSpecific *) nil_chk(obj)) getApplicationTag]) {
        case LibOrgBouncycastleAsn1EacEACTags_CERTIFICATE_CONTENT_TEMPLATE:
        self->certificateBody_ = LibOrgBouncycastleAsn1EacCertificateBody_getInstanceWithId_(obj);
        valid |= LibOrgBouncycastleAsn1EacCVCertificateRequest_bodyValid;
        break;
        case LibOrgBouncycastleAsn1EacEACTags_STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP:
        self->innerSignature_ = [obj getContents];
        valid |= LibOrgBouncycastleAsn1EacCVCertificateRequest_signValid;
        break;
        default:
        @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"Invalid tag, not an CV X509Certificate Request element:", [obj getApplicationTag]));
      }
    }
    if ((valid & (LibOrgBouncycastleAsn1EacCVCertificateRequest_bodyValid | LibOrgBouncycastleAsn1EacCVCertificateRequest_signValid)) == 0) {
      @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"Invalid CARDHOLDER_CERTIFICATE in request:", [request getApplicationTag]));
    }
  }
  else {
    @throw new_JavaIoIOException_initWithNSString_(JreStrcat("$I", @"not a CARDHOLDER_CERTIFICATE in request:", [request getApplicationTag]));
  }
}

LibOrgBouncycastleAsn1EacCVCertificateRequest *LibOrgBouncycastleAsn1EacCVCertificateRequest_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1EacCVCertificateRequest_initialize();
  if ([obj isKindOfClass:[LibOrgBouncycastleAsn1EacCVCertificateRequest class]]) {
    return (LibOrgBouncycastleAsn1EacCVCertificateRequest *) obj;
  }
  else if (obj != nil) {
    @try {
      return new_LibOrgBouncycastleAsn1EacCVCertificateRequest_initWithLibOrgBouncycastleAsn1ASN1ApplicationSpecific_(LibOrgBouncycastleAsn1ASN1ApplicationSpecific_getInstanceWithId_(obj));
    }
    @catch (JavaIoIOException *e) {
      @throw new_LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"unable to parse data: ", [e getMessage]), e);
    }
  }
  return nil;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1EacCVCertificateRequest)