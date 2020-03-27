//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/pqc/crypto/gmss/GMSSSigner.java
//

#include "Arrays.h"
#include "CipherParameters.h"
#include "CryptoServicesRegistrar.h"
#include "Digest.h"
#include "GMSSDigestProvider.h"
#include "GMSSKeyParameters.h"
#include "GMSSParameters.h"
#include "GMSSPrivateKeyParameters.h"
#include "GMSSPublicKeyParameters.h"
#include "GMSSRandom.h"
#include "GMSSSigner.h"
#include "GMSSUtil.h"
#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "ParametersWithRandom.h"
#include "WinternitzOTSVerify.h"
#include "WinternitzOTSignature.h"
#include "java/io/PrintStream.h"
#include "java/lang/IllegalStateException.h"
#include "java/lang/System.h"
#include "java/security/SecureRandom.h"

@interface LibOrgBouncycastlePqcCryptoGmssGMSSSigner () {
 @public
  LibOrgBouncycastlePqcCryptoGmssUtilGMSSUtil *gmssUtil_;
  IOSByteArray *pubKeyBytes_;
  id<LibOrgBouncycastleCryptoDigest> messDigestTrees_;
  jint mdLength_;
  jint numLayer_;
  id<LibOrgBouncycastleCryptoDigest> messDigestOTS_;
  LibOrgBouncycastlePqcCryptoGmssUtilWinternitzOTSignature *ots_;
  id<LibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider> digestProvider_;
  IOSIntArray *index_;
  IOSObjectArray *currentAuthPaths_;
  IOSObjectArray *subtreeRootSig_;
  LibOrgBouncycastlePqcCryptoGmssGMSSParameters *gmssPS_;
  LibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom *gmssRandom_;
  JavaSecuritySecureRandom *random_;
}

- (void)initSign OBJC_METHOD_FAMILY_NONE;

- (void)initVerify OBJC_METHOD_FAMILY_NONE;

@end

J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, gmssUtil_, LibOrgBouncycastlePqcCryptoGmssUtilGMSSUtil *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, pubKeyBytes_, IOSByteArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, messDigestTrees_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, messDigestOTS_, id<LibOrgBouncycastleCryptoDigest>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, ots_, LibOrgBouncycastlePqcCryptoGmssUtilWinternitzOTSignature *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, digestProvider_, id<LibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider>)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, index_, IOSIntArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, currentAuthPaths_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, subtreeRootSig_, IOSObjectArray *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, gmssPS_, LibOrgBouncycastlePqcCryptoGmssGMSSParameters *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, gmssRandom_, LibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom *)
J2OBJC_FIELD_SETTER(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, random_, JavaSecuritySecureRandom *)

__attribute__((unused)) static void LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initSign(LibOrgBouncycastlePqcCryptoGmssGMSSSigner *self);

__attribute__((unused)) static void LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initVerify(LibOrgBouncycastlePqcCryptoGmssGMSSSigner *self);

@implementation LibOrgBouncycastlePqcCryptoGmssGMSSSigner

- (instancetype)initWithLibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider:(id<LibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider>)digest {
  LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initWithLibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider_(self, digest);
  return self;
}

- (void)init__WithBoolean:(jboolean)forSigning
withLibOrgBouncycastleCryptoCipherParameters:(id<LibOrgBouncycastleCryptoCipherParameters>)param {
  if (forSigning) {
    if ([param isKindOfClass:[LibOrgBouncycastleCryptoParamsParametersWithRandom class]]) {
      LibOrgBouncycastleCryptoParamsParametersWithRandom *rParam = (LibOrgBouncycastleCryptoParamsParametersWithRandom *) param;
      self->random_ = [((LibOrgBouncycastleCryptoParamsParametersWithRandom *) nil_chk(rParam)) getRandom];
      self->key_ = (LibOrgBouncycastlePqcCryptoGmssGMSSPrivateKeyParameters *) cast_chk([rParam getParameters], [LibOrgBouncycastlePqcCryptoGmssGMSSPrivateKeyParameters class]);
      LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initSign(self);
    }
    else {
      self->random_ = LibOrgBouncycastleCryptoCryptoServicesRegistrar_getSecureRandom();
      self->key_ = (LibOrgBouncycastlePqcCryptoGmssGMSSPrivateKeyParameters *) cast_chk(param, [LibOrgBouncycastlePqcCryptoGmssGMSSPrivateKeyParameters class]);
      LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initSign(self);
    }
  }
  else {
    self->key_ = (LibOrgBouncycastlePqcCryptoGmssGMSSPublicKeyParameters *) cast_chk(param, [LibOrgBouncycastlePqcCryptoGmssGMSSPublicKeyParameters class]);
    LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initVerify(self);
  }
}

- (void)initSign {
  LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initSign(self);
}

- (IOSByteArray *)generateSignatureWithByteArray:(IOSByteArray *)message {
  IOSByteArray *otsSig = [IOSByteArray newArrayWithLength:mdLength_];
  IOSByteArray *authPathBytes;
  IOSByteArray *indexBytes;
  otsSig = [((LibOrgBouncycastlePqcCryptoGmssUtilWinternitzOTSignature *) nil_chk(ots_)) getSignatureWithByteArray:message];
  authPathBytes = [((LibOrgBouncycastlePqcCryptoGmssUtilGMSSUtil *) nil_chk(gmssUtil_)) concatenateArrayWithByteArray2:IOSObjectArray_Get(nil_chk(currentAuthPaths_), numLayer_ - 1)];
  indexBytes = [((LibOrgBouncycastlePqcCryptoGmssUtilGMSSUtil *) nil_chk(gmssUtil_)) intToBytesLittleEndianWithInt:IOSIntArray_Get(nil_chk(index_), numLayer_ - 1)];
  IOSByteArray *gmssSigFirstPart = [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(indexBytes))->size_ + ((IOSByteArray *) nil_chk(otsSig))->size_ + ((IOSByteArray *) nil_chk(authPathBytes))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(indexBytes, 0, gmssSigFirstPart, 0, indexBytes->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(otsSig, 0, gmssSigFirstPart, indexBytes->size_, otsSig->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(authPathBytes, 0, gmssSigFirstPart, (indexBytes->size_ + otsSig->size_), authPathBytes->size_);
  IOSByteArray *gmssSigNextPart = [IOSByteArray newArrayWithLength:0];
  for (jint i = numLayer_ - 1 - 1; i >= 0; i--) {
    authPathBytes = [((LibOrgBouncycastlePqcCryptoGmssUtilGMSSUtil *) nil_chk(gmssUtil_)) concatenateArrayWithByteArray2:IOSObjectArray_Get(nil_chk(currentAuthPaths_), i)];
    indexBytes = [((LibOrgBouncycastlePqcCryptoGmssUtilGMSSUtil *) nil_chk(gmssUtil_)) intToBytesLittleEndianWithInt:IOSIntArray_Get(nil_chk(index_), i)];
    IOSByteArray *helpGmssSig = [IOSByteArray newArrayWithLength:gmssSigNextPart->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(gmssSigNextPart, 0, helpGmssSig, 0, gmssSigNextPart->size_);
    gmssSigNextPart = [IOSByteArray newArrayWithLength:helpGmssSig->size_ + ((IOSByteArray *) nil_chk(indexBytes))->size_ + ((IOSByteArray *) nil_chk(IOSObjectArray_Get(nil_chk(subtreeRootSig_), i)))->size_ + ((IOSByteArray *) nil_chk(authPathBytes))->size_];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(helpGmssSig, 0, gmssSigNextPart, 0, helpGmssSig->size_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(indexBytes, 0, gmssSigNextPart, helpGmssSig->size_, indexBytes->size_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(IOSObjectArray_Get(nil_chk(subtreeRootSig_), i), 0, gmssSigNextPart, (helpGmssSig->size_ + indexBytes->size_), ((IOSByteArray *) nil_chk(IOSObjectArray_Get(subtreeRootSig_, i)))->size_);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(authPathBytes, 0, gmssSigNextPart, (helpGmssSig->size_ + indexBytes->size_ + ((IOSByteArray *) nil_chk(IOSObjectArray_Get(nil_chk(subtreeRootSig_), i)))->size_), authPathBytes->size_);
  }
  IOSByteArray *gmssSig = [IOSByteArray newArrayWithLength:gmssSigFirstPart->size_ + gmssSigNextPart->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(gmssSigFirstPart, 0, gmssSig, 0, gmssSigFirstPart->size_);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(gmssSigNextPart, 0, gmssSig, gmssSigFirstPart->size_, gmssSigNextPart->size_);
  return gmssSig;
}

- (void)initVerify {
  LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initVerify(self);
}

- (jboolean)verifySignatureWithByteArray:(IOSByteArray *)message
                           withByteArray:(IOSByteArray *)signature {
  jboolean success = false;
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestOTS_)) reset];
  LibOrgBouncycastlePqcCryptoGmssUtilWinternitzOTSVerify *otsVerify;
  jint otsSigLength;
  IOSByteArray *help = message;
  IOSByteArray *otsSig;
  IOSByteArray *otsPublicKey;
  IOSObjectArray *authPath;
  IOSByteArray *dest;
  jint nextEntry = 0;
  jint index;
  for (jint j = numLayer_ - 1; j >= 0; j--) {
    otsVerify = new_LibOrgBouncycastlePqcCryptoGmssUtilWinternitzOTSVerify_initWithLibOrgBouncycastleCryptoDigest_withInt_([((id<LibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider>) nil_chk(digestProvider_)) get], IOSIntArray_Get(nil_chk([((LibOrgBouncycastlePqcCryptoGmssGMSSParameters *) nil_chk(gmssPS_)) getWinternitzParameter]), j));
    otsSigLength = [otsVerify getSignatureLength];
    message = help;
    index = [((LibOrgBouncycastlePqcCryptoGmssUtilGMSSUtil *) nil_chk(gmssUtil_)) bytesToIntLittleEndianWithByteArray:signature withInt:nextEntry];
    nextEntry += 4;
    otsSig = [IOSByteArray newArrayWithLength:otsSigLength];
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(signature, nextEntry, otsSig, 0, otsSigLength);
    nextEntry += otsSigLength;
    otsPublicKey = [otsVerify VerifyWithByteArray:message withByteArray:otsSig];
    if (otsPublicKey == nil) {
      [((JavaIoPrintStream *) nil_chk(JreLoadStatic(JavaLangSystem, err))) printlnWithNSString:@"OTS Public Key is null in GMSSSignature.verify"];
      return false;
    }
    authPath = [IOSByteArray newArrayWithDimensions:2 lengths:(jint[]){ IOSIntArray_Get(nil_chk([((LibOrgBouncycastlePqcCryptoGmssGMSSParameters *) nil_chk(gmssPS_)) getHeightOfTrees]), j), mdLength_ }];
    for (jint i = 0; i < authPath->size_; i++) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(signature, nextEntry, IOSObjectArray_Get(authPath, i), 0, mdLength_);
      nextEntry = nextEntry + mdLength_;
    }
    help = [IOSByteArray newArrayWithLength:mdLength_];
    help = otsPublicKey;
    jint count = JreLShift32(1, authPath->size_);
    count = count + index;
    for (jint i = 0; i < authPath->size_; i++) {
      dest = [IOSByteArray newArrayWithLength:JreLShift32(mdLength_, 1)];
      if ((count % 2) == 0) {
        JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(help, 0, dest, 0, mdLength_);
        JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(IOSObjectArray_Get(authPath, i), 0, dest, mdLength_, mdLength_);
        count = count / 2;
      }
      else {
        JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(IOSObjectArray_Get(authPath, i), 0, dest, 0, mdLength_);
        JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(help, 0, dest, mdLength_, help->size_);
        count = (count - 1) / 2;
      }
      [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestTrees_)) updateWithByteArray:dest withInt:0 withInt:dest->size_];
      help = [IOSByteArray newArrayWithLength:[((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestTrees_)) getDigestSize]];
      [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(messDigestTrees_)) doFinalWithByteArray:help withInt:0];
    }
  }
  if (LibOrgBouncycastleUtilArrays_areEqualWithByteArray_withByteArray_(pubKeyBytes_, help)) {
    success = true;
  }
  return success;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "V", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithLibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider:);
  methods[1].selector = @selector(init__WithBoolean:withLibOrgBouncycastleCryptoCipherParameters:);
  methods[2].selector = @selector(initSign);
  methods[3].selector = @selector(generateSignatureWithByteArray:);
  methods[4].selector = @selector(initVerify);
  methods[5].selector = @selector(verifySignatureWithByteArray:withByteArray:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "gmssUtil_", "LLibOrgBouncycastlePqcCryptoGmssUtilGMSSUtil;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "pubKeyBytes_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "messDigestTrees_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "mdLength_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "numLayer_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "messDigestOTS_", "LLibOrgBouncycastleCryptoDigest;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "ots_", "LLibOrgBouncycastlePqcCryptoGmssUtilWinternitzOTSignature;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "digestProvider_", "LLibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "index_", "[I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "currentAuthPaths_", "[[[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "subtreeRootSig_", "[[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "gmssPS_", "LLibOrgBouncycastlePqcCryptoGmssGMSSParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "gmssRandom_", "LLibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "key_", "LLibOrgBouncycastlePqcCryptoGmssGMSSKeyParameters;", .constantValue.asLong = 0, 0x0, -1, -1, -1, -1 },
    { "random_", "LJavaSecuritySecureRandom;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LLibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider;", "init", "ZLLibOrgBouncycastleCryptoCipherParameters;", "generateSignature", "[B", "verifySignature", "[B[B" };
  static const J2ObjcClassInfo _LibOrgBouncycastlePqcCryptoGmssGMSSSigner = { "GMSSSigner", "lib.org.bouncycastle.pqc.crypto.gmss", ptrTable, methods, fields, 7, 0x1, 6, 15, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastlePqcCryptoGmssGMSSSigner;
}

@end

void LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initWithLibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider_(LibOrgBouncycastlePqcCryptoGmssGMSSSigner *self, id<LibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider> digest) {
  NSObject_init(self);
  self->gmssUtil_ = new_LibOrgBouncycastlePqcCryptoGmssUtilGMSSUtil_init();
  self->digestProvider_ = digest;
  self->messDigestTrees_ = [((id<LibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider>) nil_chk(digest)) get];
  self->messDigestOTS_ = self->messDigestTrees_;
  self->mdLength_ = [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTrees_)) getDigestSize];
  self->gmssRandom_ = new_LibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom_initWithLibOrgBouncycastleCryptoDigest_(self->messDigestTrees_);
}

LibOrgBouncycastlePqcCryptoGmssGMSSSigner *new_LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initWithLibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider_(id<LibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider> digest) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, initWithLibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider_, digest)
}

LibOrgBouncycastlePqcCryptoGmssGMSSSigner *create_LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initWithLibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider_(id<LibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider> digest) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastlePqcCryptoGmssGMSSSigner, initWithLibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider_, digest)
}

void LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initSign(LibOrgBouncycastlePqcCryptoGmssGMSSSigner *self) {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTrees_)) reset];
  LibOrgBouncycastlePqcCryptoGmssGMSSPrivateKeyParameters *gmssPrivateKey = (LibOrgBouncycastlePqcCryptoGmssGMSSPrivateKeyParameters *) cast_chk(self->key_, [LibOrgBouncycastlePqcCryptoGmssGMSSPrivateKeyParameters class]);
  if ([((LibOrgBouncycastlePqcCryptoGmssGMSSPrivateKeyParameters *) nil_chk(gmssPrivateKey)) isUsed]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"Private key already used");
  }
  if ([gmssPrivateKey getIndexWithInt:0] >= [gmssPrivateKey getNumLeafsWithInt:0]) {
    @throw new_JavaLangIllegalStateException_initWithNSString_(@"No more signatures can be generated");
  }
  self->gmssPS_ = [gmssPrivateKey getParameters];
  self->numLayer_ = [((LibOrgBouncycastlePqcCryptoGmssGMSSParameters *) nil_chk(self->gmssPS_)) getNumOfLayers];
  IOSByteArray *seed = IOSObjectArray_Get(nil_chk([gmssPrivateKey getCurrentSeeds]), self->numLayer_ - 1);
  IOSByteArray *OTSSeed = [IOSByteArray newArrayWithLength:self->mdLength_];
  IOSByteArray *dummy = [IOSByteArray newArrayWithLength:self->mdLength_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(seed, 0, dummy, 0, self->mdLength_);
  OTSSeed = [((LibOrgBouncycastlePqcCryptoGmssUtilGMSSRandom *) nil_chk(self->gmssRandom_)) nextSeedWithByteArray:dummy];
  self->ots_ = new_LibOrgBouncycastlePqcCryptoGmssUtilWinternitzOTSignature_initWithByteArray_withLibOrgBouncycastleCryptoDigest_withInt_(OTSSeed, [((id<LibOrgBouncycastlePqcCryptoGmssGMSSDigestProvider>) nil_chk(self->digestProvider_)) get], IOSIntArray_Get(nil_chk([((LibOrgBouncycastlePqcCryptoGmssGMSSParameters *) nil_chk(self->gmssPS_)) getWinternitzParameter]), self->numLayer_ - 1));
  IOSObjectArray *helpCurrentAuthPaths = [gmssPrivateKey getCurrentAuthPaths];
  self->currentAuthPaths_ = [IOSObjectArray newArrayWithLength:self->numLayer_ type:IOSClass_byteArray(2)];
  for (jint j = 0; j < self->numLayer_; j++) {
    (void) IOSObjectArray_SetAndConsume(nil_chk(self->currentAuthPaths_), j, [IOSByteArray newArrayWithDimensions:2 lengths:(jint[]){ ((IOSObjectArray *) nil_chk(IOSObjectArray_Get(nil_chk(helpCurrentAuthPaths), j)))->size_, self->mdLength_ }]);
    for (jint i = 0; i < ((IOSObjectArray *) nil_chk(IOSObjectArray_Get(helpCurrentAuthPaths, j)))->size_; i++) {
      JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(IOSObjectArray_Get(nil_chk(IOSObjectArray_Get(helpCurrentAuthPaths, j)), i), 0, IOSObjectArray_Get(nil_chk(IOSObjectArray_Get(nil_chk(self->currentAuthPaths_), j)), i), 0, self->mdLength_);
    }
  }
  self->index_ = [IOSIntArray newArrayWithLength:self->numLayer_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_([gmssPrivateKey getIndex], 0, self->index_, 0, self->numLayer_);
  IOSByteArray *helpSubtreeRootSig;
  self->subtreeRootSig_ = [IOSObjectArray newArrayWithLength:self->numLayer_ - 1 type:IOSClass_byteArray(1)];
  for (jint i = 0; i < self->numLayer_ - 1; i++) {
    helpSubtreeRootSig = [gmssPrivateKey getSubtreeRootSigWithInt:i];
    (void) IOSObjectArray_SetAndConsume(nil_chk(self->subtreeRootSig_), i, [IOSByteArray newArrayWithLength:((IOSByteArray *) nil_chk(helpSubtreeRootSig))->size_]);
    JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(helpSubtreeRootSig, 0, IOSObjectArray_Get(self->subtreeRootSig_, i), 0, helpSubtreeRootSig->size_);
  }
  [gmssPrivateKey markUsed];
}

void LibOrgBouncycastlePqcCryptoGmssGMSSSigner_initVerify(LibOrgBouncycastlePqcCryptoGmssGMSSSigner *self) {
  [((id<LibOrgBouncycastleCryptoDigest>) nil_chk(self->messDigestTrees_)) reset];
  LibOrgBouncycastlePqcCryptoGmssGMSSPublicKeyParameters *gmssPublicKey = (LibOrgBouncycastlePqcCryptoGmssGMSSPublicKeyParameters *) cast_chk(self->key_, [LibOrgBouncycastlePqcCryptoGmssGMSSPublicKeyParameters class]);
  self->pubKeyBytes_ = [((LibOrgBouncycastlePqcCryptoGmssGMSSPublicKeyParameters *) nil_chk(gmssPublicKey)) getPublicKey];
  self->gmssPS_ = [gmssPublicKey getParameters];
  self->numLayer_ = [((LibOrgBouncycastlePqcCryptoGmssGMSSParameters *) nil_chk(self->gmssPS_)) getNumOfLayers];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastlePqcCryptoGmssGMSSSigner)
