//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/openpgp/PGPV3SignatureGenerator.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "MPInteger.h"
#include "OnePassSignaturePacket.h"
#include "PGPContentSigner.h"
#include "PGPContentSignerBuilder.h"
#include "PGPException.h"
#include "PGPOnePassSignature.h"
#include "PGPPrivateKey.h"
#include "PGPRuntimeOperationException.h"
#include "PGPSignature.h"
#include "PGPUtil.h"
#include "PGPV3SignatureGenerator.h"
#include "PublicKeyAlgorithmTags.h"
#include "SignaturePacket.h"
#include "java/io/ByteArrayOutputStream.h"
#include "java/io/IOException.h"
#include "java/io/OutputStream.h"
#include "java/math/BigInteger.h"
#include "java/util/Date.h"

@interface LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator () {
 @public
  jbyte lastb_;
  JavaIoOutputStream *sigOut_;
  id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> contentSignerBuilder_;
  id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner> contentSigner_;
  jint sigType_;
  jint providedKeyAlgorithm_;
}

- (void)byteUpdateWithByte:(jbyte)b;

- (void)blockUpdateWithByteArray:(IOSByteArray *)block
                         withInt:(jint)off
                         withInt:(jint)len;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator, sigOut_, JavaIoOutputStream *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator, contentSignerBuilder_, id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator, contentSigner_, id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>)

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_byteUpdateWithByte_(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator *self, jbyte b);

__attribute__((unused)) static void LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_blockUpdateWithByteArray_withInt_withInt_(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator *self, IOSByteArray *block, jint off, jint len);

@implementation LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator

- (instancetype)initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder:(id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder>)contentSignerBuilder {
  LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_(self, contentSignerBuilder);
  return self;
}

- (void)init__WithInt:(jint)signatureType
withLibOrgBouncycastleOpenpgpPGPPrivateKey:(LibOrgBouncycastleOpenpgpPGPPrivateKey *)key {
  contentSigner_ = [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder>) nil_chk(contentSignerBuilder_)) buildWithInt:signatureType withLibOrgBouncycastleOpenpgpPGPPrivateKey:key];
  sigOut_ = [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getOutputStream];
  sigType_ = [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getType];
  lastb_ = 0;
  if (providedKeyAlgorithm_ >= 0 && providedKeyAlgorithm_ != [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getKeyAlgorithm]) {
    @throw new_LibOrgBouncycastleOpenpgpPGPException_initWithNSString_(@"key algorithm mismatch");
  }
}

- (void)updateWithByte:(jbyte)b {
  if (sigType_ == LibOrgBouncycastleOpenpgpPGPSignature_CANONICAL_TEXT_DOCUMENT) {
    if (b == 0x000d) {
      LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_byteUpdateWithByte_(self, (jbyte) 0x000d);
      LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_byteUpdateWithByte_(self, (jbyte) 0x000a);
    }
    else if (b == 0x000a) {
      if (lastb_ != 0x000d) {
        LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_byteUpdateWithByte_(self, (jbyte) 0x000d);
        LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_byteUpdateWithByte_(self, (jbyte) 0x000a);
      }
    }
    else {
      LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_byteUpdateWithByte_(self, b);
    }
    lastb_ = b;
  }
  else {
    LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_byteUpdateWithByte_(self, b);
  }
}

- (void)updateWithByteArray:(IOSByteArray *)b {
  [self updateWithByteArray:b withInt:0 withInt:((IOSByteArray *) nil_chk(b))->size_];
}

- (void)updateWithByteArray:(IOSByteArray *)b
                    withInt:(jint)off
                    withInt:(jint)len {
  if (sigType_ == LibOrgBouncycastleOpenpgpPGPSignature_CANONICAL_TEXT_DOCUMENT) {
    jint finish = off + len;
    for (jint i = off; i != finish; i++) {
      [self updateWithByte:IOSByteArray_Get(nil_chk(b), i)];
    }
  }
  else {
    LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_blockUpdateWithByteArray_withInt_withInt_(self, b, off, len);
  }
}

- (void)byteUpdateWithByte:(jbyte)b {
  LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_byteUpdateWithByte_(self, b);
}

- (void)blockUpdateWithByteArray:(IOSByteArray *)block
                         withInt:(jint)off
                         withInt:(jint)len {
  LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_blockUpdateWithByteArray_withInt_withInt_(self, block, off, len);
}

- (LibOrgBouncycastleOpenpgpPGPOnePassSignature *)generateOnePassVersionWithBoolean:(jboolean)isNested {
  return new_LibOrgBouncycastleOpenpgpPGPOnePassSignature_initWithLibOrgBouncycastleBcpgOnePassSignaturePacket_(new_LibOrgBouncycastleBcpgOnePassSignaturePacket_initWithInt_withInt_withInt_withLong_withBoolean_(sigType_, [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getHashAlgorithm], [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getKeyAlgorithm], [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getKeyID], isNested));
}

- (LibOrgBouncycastleOpenpgpPGPSignature *)generate {
  jlong creationTime = [new_JavaUtilDate_init() getTime] / 1000;
  JavaIoByteArrayOutputStream *sOut = new_JavaIoByteArrayOutputStream_init();
  [sOut writeWithInt:sigType_];
  [sOut writeWithInt:(jbyte) (JreRShift64(creationTime, 24))];
  [sOut writeWithInt:(jbyte) (JreRShift64(creationTime, 16))];
  [sOut writeWithInt:(jbyte) (JreRShift64(creationTime, 8))];
  [sOut writeWithInt:(jbyte) creationTime];
  IOSByteArray *hData = [sOut toByteArray];
  LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_blockUpdateWithByteArray_withInt_withInt_(self, hData, 0, ((IOSByteArray *) nil_chk(hData))->size_);
  IOSObjectArray *sigValues;
  if ([((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getKeyAlgorithm] == LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_SIGN || [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getKeyAlgorithm] == LibOrgBouncycastleBcpgPublicKeyAlgorithmTags_RSA_GENERAL) {
    sigValues = [IOSObjectArray newArrayWithLength:1 type:LibOrgBouncycastleBcpgMPInteger_class_()];
    (void) IOSObjectArray_SetAndConsume(sigValues, 0, new_LibOrgBouncycastleBcpgMPInteger_initWithJavaMathBigInteger_(new_JavaMathBigInteger_initWithInt_withByteArray_(1, [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getSignature])));
  }
  else {
    sigValues = LibOrgBouncycastleOpenpgpPGPUtil_dsaSigToMpiWithByteArray_([((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getSignature]);
  }
  IOSByteArray *digest = [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getDigest];
  IOSByteArray *fingerPrint = [IOSByteArray newArrayWithLength:2];
  *IOSByteArray_GetRef(fingerPrint, 0) = IOSByteArray_Get(nil_chk(digest), 0);
  *IOSByteArray_GetRef(fingerPrint, 1) = IOSByteArray_Get(digest, 1);
  return new_LibOrgBouncycastleOpenpgpPGPSignature_initWithLibOrgBouncycastleBcpgSignaturePacket_(new_LibOrgBouncycastleBcpgSignaturePacket_initWithInt_withInt_withLong_withInt_withInt_withLong_withByteArray_withLibOrgBouncycastleBcpgMPIntegerArray_(3, [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getType], [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getKeyID], [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getKeyAlgorithm], [((id<LibOrgBouncycastleOpenpgpOperatorPGPContentSigner>) nil_chk(contentSigner_)) getHashAlgorithm], creationTime * 1000, fingerPrint, sigValues));
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, 3, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 6, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 4, 7, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 8, 5, -1, -1, -1, -1 },
    { NULL, "V", 0x2, 9, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPOnePassSignature;", 0x1, 10, 11, 3, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleOpenpgpPGPSignature;", 0x1, -1, -1, 3, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder:);
  methods[1].selector = @selector(init__WithInt:withLibOrgBouncycastleOpenpgpPGPPrivateKey:);
  methods[2].selector = @selector(updateWithByte:);
  methods[3].selector = @selector(updateWithByteArray:);
  methods[4].selector = @selector(updateWithByteArray:withInt:withInt:);
  methods[5].selector = @selector(byteUpdateWithByte:);
  methods[6].selector = @selector(blockUpdateWithByteArray:withInt:withInt:);
  methods[7].selector = @selector(generateOnePassVersionWithBoolean:);
  methods[8].selector = @selector(generate);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "lastb_", "B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sigOut_", "LJavaIoOutputStream;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "contentSignerBuilder_", "LLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "contentSigner_", "LLibOrgBouncycastleOpenpgpOperatorPGPContentSigner;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "sigType_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "providedKeyAlgorithm_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder;", "init", "ILLibOrgBouncycastleOpenpgpPGPPrivateKey;", "LLibOrgBouncycastleOpenpgpPGPException;", "update", "B", "[B", "[BII", "byteUpdate", "blockUpdate", "generateOnePassVersion", "Z" };
  static const J2ObjcClassInfo _LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator = { "PGPV3SignatureGenerator", "lib.org.bouncycastle.openpgp", ptrTable, methods, fields, 7, 0x1, 9, 6, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator;
}

@end

void LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator *self, id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> contentSignerBuilder) {
  NSObject_init(self);
  self->providedKeyAlgorithm_ = -1;
  self->contentSignerBuilder_ = contentSignerBuilder;
}

LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator *new_LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_(id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> contentSignerBuilder) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator, initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_, contentSignerBuilder)
}

LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator *create_LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_(id<LibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder> contentSignerBuilder) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator, initWithLibOrgBouncycastleOpenpgpOperatorPGPContentSignerBuilder_, contentSignerBuilder)
}

void LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_byteUpdateWithByte_(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator *self, jbyte b) {
  @try {
    [((JavaIoOutputStream *) nil_chk(self->sigOut_)) writeWithInt:b];
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPRuntimeOperationException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"unable to update signature: ", [e getMessage]), e);
  }
}

void LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator_blockUpdateWithByteArray_withInt_withInt_(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator *self, IOSByteArray *block, jint off, jint len) {
  @try {
    [((JavaIoOutputStream *) nil_chk(self->sigOut_)) writeWithByteArray:block withInt:off withInt:len];
  }
  @catch (JavaIoIOException *e) {
    @throw new_LibOrgBouncycastleOpenpgpPGPRuntimeOperationException_initWithNSString_withJavaLangThrowable_(JreStrcat("$$", @"unable to update signature: ", [e getMessage]), e);
  }
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleOpenpgpPGPV3SignatureGenerator)