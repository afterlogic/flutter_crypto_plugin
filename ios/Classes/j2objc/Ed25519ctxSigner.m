//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/crypto/signers/Ed25519ctxSigner.java
//

#include "Arrays.h"
#include "CipherParameters.h"
#include "Ed25519.h"
#include "Ed25519PrivateKeyParameters.h"
#include "Ed25519PublicKeyParameters.h"
#include "Ed25519ctxSigner.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/lang/IllegalStateException.h"

@class LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer;

@interface LibOrgBouncycastleCryptoSignersEd25519ctxSigner () {
 @public
  LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *buffer_;
  IOSByteArray *context_;
  jboolean forSigning_;
  LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *privateKey_;
  LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *publicKey_;
}

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersEd25519ctxSigner, buffer_, LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersEd25519ctxSigner, context_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersEd25519ctxSigner, privateKey_, LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleCryptoSignersEd25519ctxSigner, publicKey_, LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)

@interface LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer : JavaIoByteArrayOutputStream

- (instancetype)init;

- (IOSByteArray *)generateSignatureWithLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *)privateKey
                                    withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)publicKey
                                                                                   withByteArray:(IOSByteArray *)ctx;

- (jboolean)verifySignatureWithLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)publicKey
                                                                          withByteArray:(IOSByteArray *)ctx
                                                                          withByteArray:(IOSByteArray *)signature;

- (void)reset;

@end

J2OBJC_EMPTY_STATIC_INIT(LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer)

__attribute__((unused)) static void LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer_init(LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *self);

__attribute__((unused)) static LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *new_LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer_init(void) NS_RETURNS_RETAINED;

__attribute__((unused)) static LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *create_LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer_init(void);

J2OBJC_TYPE_LITERAL_HEADER(LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer)

@implementation LibOrgBouncycastleCryptoSignersEd25519ctxSigner

- (instancetype)initWithByteArray:(IOSByteArray *)context {
  LibOrgBouncycastleCryptoSignersEd25519ctxSigner_initWithByteArray_(self, context);
  return self;
}

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)parameters {
  self->forSigning_ = forSigning;
  if (forSigning) {
    self->privateKey_ = (LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *) cast_chk(parameters, [LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters class]);
    self->publicKey_ = [((LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *) nil_chk(privateKey_)) generatePublicKey];
  }
  else {
    self->privateKey_ = nil;
    self->publicKey_ = (LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *) cast_chk(parameters, [LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters class]);
  }
  [self reset];
}

- (void)updateWithByte:(jbyte)b {
  [((LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *) nil_chk(buffer_)) writeWithInt:b];
}

- (void)updateWithByteArray:(IOSByteArray *)buf
                    withInt:(jint)off
                    withInt:(jint)len {
  [((LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *) nil_chk(buffer_)) writeWithByteArray:buf withInt:off withInt:len];
}

- (IOSByteArray *)generateSignature {
  if (!forSigning_ || nil == privateKey_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Ed25519ctxSigner not initialised for signature generation.");
  }
  return [((LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *) nil_chk(buffer_)) generateSignatureWithLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters:privateKey_ withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:publicKey_ withByteArray:context_];
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)signature {
  if (forSigning_ || nil == publicKey_) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Ed25519ctxSigner not initialised for verification");
  }
  return [((LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *) nil_chk(buffer_)) verifySignatureWithLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:publicKey_ withByteArray:context_ withByteArray:signature];
}

- (void)reset {
  [((LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *) nil_chk(buffer_)) reset];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 6, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(updateWithByte:);
  methods[3].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[4].selector = @selector(generateSignature);
  methods[5].selector = @selector(verifySignatureWithByteArray:);
  methods[6].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "buffer_", "LLibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "context_", "[B", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "forSigning_", "Z", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "privateKey_", "LLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "publicKey_", "LLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[B", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "update", "B", "[BII", "verifySignature", "LLibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSignersEd25519ctxSigner = { "Ed25519ctxSigner", "lib.org.bouncycastle.crypto.signers", ptrTable, methods, fields, 7, 0x1, 7, 5, -1, 7, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSignersEd25519ctxSigner;
}

@end

void LibOrgBouncycastleCryptoSignersEd25519ctxSigner_initWithByteArray_(LibOrgBouncycastleCryptoSignersEd25519ctxSigner *self, IOSByteArray *context) {
  NSObject_init(self);
  self->buffer_ = new_LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer_init();
  self->context_ = LibOrgBouncycastleUtilArrays_cloneWithByteArray_(context);
}

LibOrgBouncycastleCryptoSignersEd25519ctxSigner *new_LibOrgBouncycastleCryptoSignersEd25519ctxSigner_initWithByteArray_(IOSByteArray *context) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersEd25519ctxSigner, initWithByteArray_, context)
}

LibOrgBouncycastleCryptoSignersEd25519ctxSigner *create_LibOrgBouncycastleCryptoSignersEd25519ctxSigner_initWithByteArray_(IOSByteArray *context) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersEd25519ctxSigner, initWithByteArray_, context)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSignersEd25519ctxSigner)

@implementation LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSByteArray *)generateSignatureWithLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *)privateKey
                                    withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)publicKey
                                                                                   withByteArray:(IOSByteArray *)ctx {
  @synchronized(self) {
    IOSByteArray *signature = [IOSByteArray newArrayWithLength:LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters_SIGNATURE_SIZE];
    [((LibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters *) nil_chk(privateKey)) signWithInt:LibOrgBouncycastleMathEcRfc8032Ed25519_Algorithm_Ed25519ctx withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:publicKey withByteArray:ctx withByteArray:buf_ withInt:0 withInt:count_ withByteArray:signature withInt:0];
    [self reset];
    return signature;
  }
}

- (jboolean)verifySignatureWithLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:(LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *)publicKey
                                                                          withByteArray:(IOSByteArray *)ctx
                                                                          withByteArray:(IOSByteArray *)signature {
  @synchronized(self) {
    IOSByteArray *pk = [((LibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters *) nil_chk(publicKey)) getEncoded];
    jboolean result = LibOrgBouncycastleMathEcRfc8032Ed25519_verifyWithByteArray_withInt_withByteArray_withInt_withByteArray_withByteArray_withInt_withInt_(signature, 0, pk, 0, ctx, buf_, 0, count_);
    [self reset];
    return result;
  }
}

- (void)reset {
  @synchronized(self) {
    LibOrgBouncycastleUtilArrays_fillWithByteArray_withInt_withInt_withByte_(buf_, 0, count_, (jbyte) 0);
    self->count_ = 0;
  }
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x20, 0, 1, -1, -1, -1, -1 },
    { NULL, "Z", 0x20, 2, 3, -1, -1, -1, -1 },
    { NULL, "V", 0x21, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(generateSignatureWithLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters:withLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:withByteArray:);
  methods[2].selector = @selector(verifySignatureWithLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters:withByteArray:withByteArray:);
  methods[3].selector = @selector(reset);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "generateSignature", "LLibOrgBouncycastleCryptoParamsEd25519PrivateKeyParameters;LLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters;[B", "verifySignature", "LLibOrgBouncycastleCryptoParamsEd25519PublicKeyParameters;[B[B", "LLibOrgBouncycastleCryptoSignersEd25519ctxSigner;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer = { "Buffer", "lib.org.bouncycastle.crypto.signers", ptrTable, methods, NULL, 7, 0xa, 4, 0, 4, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer;
}

@end

void LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer_init(LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *self) {
  JavaIoByteArrayOutputStream_init(self);
}

LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *new_LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer_init() {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer, init)
}

LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer *create_LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer_init() {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleCryptoSignersEd25519ctxSigner_Buffer)
