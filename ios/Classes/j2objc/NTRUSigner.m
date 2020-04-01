//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/ntru/NTRUSigner.java
//

#include "CipherParameters.h"
#include "Digest.h"
#include "IOSPrimitiveArray.h"
#include "IntegerPolynomial.h"
#include "J2ObjC_source.h"
#include "NTRUSigner.h"
#include "NTRUSignerPrng.h"
#include "NTRUSigningParameters.h"
#include "NTRUSigningPrivateKeyParameters.h"
#include "NTRUSigningPublicKeyParameters.h"
#include "PqcMathPolynomial.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/Integer.h"
#include "java/nio/Buffer.h"
#include "java/nio/ByteBuffer.h"

@interface LibOrgBouncycastlePqcCryptoNtruNTRUSigner () {
 @public
  LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params_;
  id<LibOrgBouncycastleCryptoDigest> hashAlg_;
  LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *signingKeyPair_;
  LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *verificationKey_;
}

- (IOSByteArray *)signHashWithByteArray:(IOSByteArray *)msgHash
withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *)kp;

- (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)signWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)i
                                                            withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *)kp;

- (jboolean)verifyHashWithByteArray:(IOSByteArray *)msgHash
                      withByteArray:(IOSByteArray *)sig
withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *)pub;

- (jboolean)verifyWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)i
                  withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)s
                  withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)h;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSigner, params_, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSigner, hashAlg_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSigner, signingKeyPair_, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoNtruNTRUSigner, verificationKey_, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *)

__attribute__((unused)) static IOSByteArray *LibOrgBouncycastlePqcCryptoNtruNTRUSigner_signHashWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigner *self, IOSByteArray *msgHash, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *kp);

__attribute__((unused)) static LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *LibOrgBouncycastlePqcCryptoNtruNTRUSigner_signWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigner *self, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *i, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *kp);

__attribute__((unused)) static jboolean LibOrgBouncycastlePqcCryptoNtruNTRUSigner_verifyHashWithByteArray_withByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigner *self, IOSByteArray *msgHash, IOSByteArray *sig, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *pub);

__attribute__((unused)) static jboolean LibOrgBouncycastlePqcCryptoNtruNTRUSigner_verifyWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(LibOrgBouncycastlePqcCryptoNtruNTRUSigner *self, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *i, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *s, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h);

@implementation LibOrgBouncycastlePqcCryptoNtruNTRUSigner

- (instancetype)initWithLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *)params {
  LibOrgBouncycastlePqcCryptoNtruNTRUSigner_initWithLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(self, params);
  return self;
}

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)params {
  if (forSigning) {
    self->signingKeyPair_ = (LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *) cast_chk(params, [LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters class]);
  }
  else {
    self->verificationKey_ = (LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *) cast_chk(params, [LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters class]);
  }
  hashAlg_ = ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *) nil_chk(self->params_))->hashAlg_;
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(hashAlg_)) reset];
}

- (void)updateWithByte:(jbyte)b {
  if (hashAlg_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Call initSign or initVerify first!");
  }
  [hashAlg_ updateWithByte:b];
}

- (void)updateWithByteArray:(IOSByteArray *)m
                    withInt:(jint)off
                    withInt:(jint)length {
  if (hashAlg_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Call initSign or initVerify first!");
  }
  [hashAlg_ updateWithByteArray:m withInt:off withInt:length];
}

- (IOSByteArray *)generateSignature {
  if (hashAlg_ == nil || signingKeyPair_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Call initSign first!");
  }
  IOSByteArray *msgHash = [IOSByteArray newArrayWithLength:[hashAlg_ getDigestSize]];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(hashAlg_)) doFinalWithByteArray:msgHash withInt:0];
  return LibOrgBouncycastlePqcCryptoNtruNTRUSigner_signHashWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_(self, msgHash, signingKeyPair_);
}

- (IOSByteArray *)signHashWithByteArray:(IOSByteArray *)msgHash
withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *)kp {
  return LibOrgBouncycastlePqcCryptoNtruNTRUSigner_signHashWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_(self, msgHash, kp);
}

- (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)signWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)i
                                                            withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *)kp {
  return LibOrgBouncycastlePqcCryptoNtruNTRUSigner_signWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_(self, i, kp);
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)sig {
  if (hashAlg_ == nil || verificationKey_ == nil) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Call initVerify first!");
  }
  IOSByteArray *msgHash = [IOSByteArray newArrayWithLength:[hashAlg_ getDigestSize]];
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(hashAlg_)) doFinalWithByteArray:msgHash withInt:0];
  return LibOrgBouncycastlePqcCryptoNtruNTRUSigner_verifyHashWithByteArray_withByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_(self, msgHash, sig, verificationKey_);
}

- (jboolean)verifyHashWithByteArray:(IOSByteArray *)msgHash
                      withByteArray:(IOSByteArray *)sig
withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters:(LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *)pub {
  return LibOrgBouncycastlePqcCryptoNtruNTRUSigner_verifyHashWithByteArray_withByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_(self, msgHash, sig, pub);
}

- (jboolean)verifyWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)i
                  withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)s
                  withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:(LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)h {
  return LibOrgBouncycastlePqcCryptoNtruNTRUSigner_verifyWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(self, i, s, h);
}

- (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *)createMsgRepWithByteArray:(IOSByteArray *)msgHash
                                                                                withInt:(jint)r {
  jint N = ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *) nil_chk(params_))->N_;
  jint q = params_->q_;
  jint c = 31 - JavaLangInteger_numberOfLeadingZerosWithInt_(q);
  jint B = (c + 7) / 8;
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *i = new_LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_initWithInt_(N);
  JavaNioByteBuffer *cbuf = JavaNioByteBuffer_allocateWithInt_(((IOSByteArray *) nil_chk(msgHash))->size_ + 4);
  (void) [((JavaNioByteBuffer *) nil_chk(cbuf)) putWithByteArray:msgHash];
  (void) [cbuf putIntWithInt:r];
  LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng *prng = new_LibOrgBouncycastlePqcCryptoNtruNTRUSignerPrng_initWithByteArray_withLibOrgBouncycastleCryptoDigest_([cbuf array], ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *) nil_chk(params_))->hashAlg_);
  for (jint t = 0; t < N; t++) {
    IOSByteArray *o = [prng nextBytesWithInt:B];
    jint hi = IOSByteArray_Get(o, ((IOSByteArray *) nil_chk(o))->size_ - 1);
    JreRShiftAssignInt(&hi, 8 * B - c);
    JreLShiftAssignInt(&hi, 8 * B - c);
    *IOSByteArray_GetRef(o, o->size_ - 1) = (jbyte) hi;
    JavaNioByteBuffer *obuf = JavaNioByteBuffer_allocateWithInt_(4);
    (void) [((JavaNioByteBuffer *) nil_chk(obuf)) putWithByteArray:o];
    (void) [obuf rewind];
    *IOSIntArray_GetRef(nil_chk(i->coeffs_), t) = JavaLangInteger_reverseBytesWithInt_([obuf getInt]);
  }
  return i;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 5, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x2, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;", 0x2, 8, 9, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 10, 11, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 12, 13, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 14, 15, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;", 0x4, 16, 17, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters:);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(updateWithByte:);
  methods[3].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[4].selector = @selector(generateSignature);
  methods[5].selector = @selector(signHashWithByteArray:withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters:);
  methods[6].selector = @selector(signWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters:);
  methods[7].selector = @selector(verifySignatureWithByteArray:);
  methods[8].selector = @selector(verifyHashWithByteArray:withByteArray:withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters:);
  methods[9].selector = @selector(verifyWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:);
  methods[10].selector = @selector(createMsgRepWithByteArray:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "params_", "LLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "hashAlg_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "signingKeyPair_", "LLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "verificationKey_", "LLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "update", "B", "[BII", "signHash", "[BLLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters;", "sign", "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;LLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters;", "verifySignature", "[B", "verifyHash", "[B[BLLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters;", "verify", "LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;LLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial;", "createMsgRep", "[BI" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoNtruNTRUSigner = { "NTRUSigner", "lib.org.bouncycastle.pqc.crypto.ntru", ptrTable, methods, fields, 7, 0x1, 11, 4, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoNtruNTRUSigner;
}

@end

void LibOrgBouncycastlePqcCryptoNtruNTRUSigner_initWithLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigner *self, LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params) {
  NSObject_init(self);
  self->params_ = params;
}

LibOrgBouncycastlePqcCryptoNtruNTRUSigner *new_LibOrgBouncycastlePqcCryptoNtruNTRUSigner_initWithLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUSigner, initWithLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_, params)
}

LibOrgBouncycastlePqcCryptoNtruNTRUSigner *create_LibOrgBouncycastlePqcCryptoNtruNTRUSigner_initWithLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *params) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoNtruNTRUSigner, initWithLibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters_, params)
}

IOSByteArray *LibOrgBouncycastlePqcCryptoNtruNTRUSigner_signHashWithByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigner *self, IOSByteArray *msgHash, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *kp) {
  jint r = 0;
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *s;
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *i;
  LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *kPub = [((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *) nil_chk(kp)) getPublicKey];
  do {
    r++;
    if (r > ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *) nil_chk(self->params_))->signFailTolerance_) {
      @throw new_JavaLangIllegalStateException_initWithNSString_(JreStrcat("$IC", @"Signing failed: too many retries (max=", self->params_->signFailTolerance_, ')'));
    }
    i = [self createMsgRepWithByteArray:msgHash withInt:r];
    s = LibOrgBouncycastlePqcCryptoNtruNTRUSigner_signWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_(self, i, kp);
  }
  while (!LibOrgBouncycastlePqcCryptoNtruNTRUSigner_verifyWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(self, i, s, ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *) nil_chk(kPub))->h_));
  IOSByteArray *rawSig = [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(s)) toBinaryWithInt:((LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *) nil_chk(self->params_))->q_];
  JavaNioByteBuffer *sbuf = JavaNioByteBuffer_allocateWithInt_(((IOSByteArray *) nil_chk(rawSig))->size_ + 4);
  (void) [((JavaNioByteBuffer *) nil_chk(sbuf)) putWithByteArray:rawSig];
  (void) [sbuf putIntWithInt:r];
  return [sbuf array];
}

LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *LibOrgBouncycastlePqcCryptoNtruNTRUSigner_signWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigner *self, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *i, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *kp) {
  jint N = ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *) nil_chk(self->params_))->N_;
  jint q = self->params_->q_;
  jint perturbationBases = self->params_->B_;
  LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *kPriv = kp;
  LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *kPub = [((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *) nil_chk(kp)) getPublicKey];
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *s = new_LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_initWithInt_(N);
  jint iLoop = perturbationBases;
  while (iLoop >= 1) {
    id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> f = ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *) nil_chk([((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *) nil_chk(kPriv)) getBasisWithInt:iLoop]))->f_;
    id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> fPrime = ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *) nil_chk([kPriv getBasisWithInt:iLoop]))->fPrime_;
    LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *y = [((id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>) nil_chk(f)) multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:i];
    [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(y)) divWithInt:q];
    y = [((id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>) nil_chk(fPrime)) multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:y];
    LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *x = [fPrime multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:i];
    [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(x)) divWithInt:q];
    x = [f multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:x];
    LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *si = y;
    [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(si)) subWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:x];
    [s addWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:si];
    LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *hi = (LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) cast_chk([((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *) nil_chk([kPriv getBasisWithInt:iLoop]))->h_)) java_clone], [LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial class]);
    if (iLoop > 1) {
      [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(hi)) subWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *) nil_chk([kPriv getBasisWithInt:iLoop - 1]))->h_];
    }
    else {
      [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(hi)) subWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *) nil_chk(kPub))->h_];
    }
    i = [si multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:hi withInt:q];
    iLoop--;
  }
  id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> f = ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *) nil_chk([((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters *) nil_chk(kPriv)) getBasisWithInt:0]))->f_;
  id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial> fPrime = ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPrivateKeyParameters_Basis *) nil_chk([kPriv getBasisWithInt:0]))->fPrime_;
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *y = [((id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>) nil_chk(f)) multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:i];
  [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(y)) divWithInt:q];
  y = [((id<LibOrgBouncycastlePqcMathNtruPolynomialPqcMathPolynomial>) nil_chk(fPrime)) multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:y];
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *x = [fPrime multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:i];
  [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(x)) divWithInt:q];
  x = [f multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:x];
  [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(y)) subWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:x];
  [s addWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:y];
  [s modPositiveWithInt:q];
  return s;
}

jboolean LibOrgBouncycastlePqcCryptoNtruNTRUSigner_verifyHashWithByteArray_withByteArray_withLibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters_(LibOrgBouncycastlePqcCryptoNtruNTRUSigner *self, IOSByteArray *msgHash, IOSByteArray *sig, LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *pub) {
  JavaNioByteBuffer *sbuf = JavaNioByteBuffer_wrapWithByteArray_(sig);
  IOSByteArray *rawSig = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(sig))->size_ - 4];
  (void) [((JavaNioByteBuffer *) nil_chk(sbuf)) getWithByteArray:rawSig];
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *s = LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_fromBinaryWithByteArray_withInt_withInt_(rawSig, ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *) nil_chk(self->params_))->N_, self->params_->q_);
  jint r = [sbuf getInt];
  return LibOrgBouncycastlePqcCryptoNtruNTRUSigner_verifyWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(self, [self createMsgRepWithByteArray:msgHash withInt:r], s, ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningPublicKeyParameters *) nil_chk(pub))->h_);
}

jboolean LibOrgBouncycastlePqcCryptoNtruNTRUSigner_verifyWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_withLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial_(LibOrgBouncycastlePqcCryptoNtruNTRUSigner *self, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *i, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *s, LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *h) {
  jint q = ((LibOrgBouncycastlePqcCryptoNtruNTRUSigningParameters *) nil_chk(self->params_))->q_;
  jdouble normBoundSq = self->params_->normBoundSq_;
  jdouble betaSq = self->params_->betaSq_;
  LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *t = [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(h)) multWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:s withInt:q];
  [((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(t)) subWithLibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial:i];
  jlong centeredNormSq = JreFpToLong(([((LibOrgBouncycastlePqcMathNtruPolynomialIntegerPolynomial *) nil_chk(s)) centeredNormSqWithInt:q] + betaSq * [t centeredNormSqWithInt:q]));
  return centeredNormSq <= normBoundSq;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoNtruNTRUSigner)