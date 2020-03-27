//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/com/afterlogic/pgp/key/generation/type/length/ElGamalLength.java
//

#include "ElGamalLength.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "java/lang/Enum.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/math/BigInteger.h"

@interface LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength () {
 @public
  jint length_;
  JavaMathBigInteger *p_;
  JavaMathBigInteger *g_;
}

@end

J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, p_, JavaMathBigInteger *)
J2OBJC_FIELD_SETTER(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, g_, JavaMathBigInteger *)

__attribute__((unused)) static void LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initWithInt_withNSString_withNSString_withNSString_withInt_(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *self, jint length, NSString *p, NSString *g, NSString *__name, jint __ordinal);

__attribute__((unused)) static LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *new_LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initWithInt_withNSString_withNSString_withNSString_withInt_(jint length, NSString *p, NSString *g, NSString *__name, jint __ordinal) NS_RETURNS_RETAINED;

J2OBJC_INITIALIZED_DEFN(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength)

LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_values_[6];

@implementation LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)_1536 {
  return JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _1536);
}

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)_2048 {
  return JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _2048);
}

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)_3072 {
  return JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _3072);
}

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)_4096 {
  return JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _4096);
}

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)_6144 {
  return JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _6144);
}

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)_8192 {
  return JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _8192);
}

- (jint)getLength {
  return length_;
}

- (JavaMathBigInteger *)getP {
  return p_;
}

- (JavaMathBigInteger *)getG {
  return g_;
}

+ (IOSObjectArray *)values {
  return LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_values();
}

+ (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *)valueOfWithNSString:(NSString *)name {
  return LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_valueOfWithNSString_(name);
}

- (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_Enum)toNSEnum {
  return (LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_Enum)[self ordinal];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaMathBigInteger;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;", 0x9, -1, -1, -1, -1, -1, -1 },
    { NULL, "LLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;", 0x9, 0, 1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getLength);
  methods[1].selector = @selector(getP);
  methods[2].selector = @selector(getG);
  methods[3].selector = @selector(values);
  methods[4].selector = @selector(valueOfWithNSString:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "_1536", "LLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;", .constantValue.asLong = 0, 0x4019, -1, 2, -1, -1 },
    { "_2048", "LLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;", .constantValue.asLong = 0, 0x4019, -1, 3, -1, -1 },
    { "_3072", "LLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;", .constantValue.asLong = 0, 0x4019, -1, 4, -1, -1 },
    { "_4096", "LLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;", .constantValue.asLong = 0, 0x4019, -1, 5, -1, -1 },
    { "_6144", "LLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;", .constantValue.asLong = 0, 0x4019, -1, 6, -1, -1 },
    { "_8192", "LLibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;", .constantValue.asLong = 0, 0x4019, -1, 7, -1, -1 },
    { "length_", "I", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "p_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "g_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "valueOf", "LNSString;", &JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _1536), &JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _2048), &JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _3072), &JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _4096), &JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _6144), &JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _8192), "Ljava/lang/Enum<Llib/com/afterlogic/pgp/key/generation/type/length/ElGamalLength;>;Llib/com/afterlogic/pgp/key/generation/type/length/KeyLength;" };
  static const J2ObjcClassInfo _LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength = { "ElGamalLength", "lib.com.afterlogic.pgp.key.generation.type.length", ptrTable, methods, fields, 7, 0x4011, 5, 9, -1, -1, -1, 8, -1 };
  return &_LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength;
}

+ (void)initialize {
  if (self == [LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength class]) {
    JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _1536) = new_LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initWithInt_withNSString_withNSString_withNSString_withInt_(1536, @"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", @"2", JreEnumConstantName(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_class_(), 0), 0);
    JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _2048) = new_LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initWithInt_withNSString_withNSString_withNSString_withInt_(2048, @"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", @"2", JreEnumConstantName(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_class_(), 1), 1);
    JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _3072) = new_LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initWithInt_withNSString_withNSString_withNSString_withInt_(3072, @"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", @"2", JreEnumConstantName(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_class_(), 2), 2);
    JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _4096) = new_LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initWithInt_withNSString_withNSString_withNSString_withInt_(4096, @"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF", @"2", JreEnumConstantName(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_class_(), 3), 3);
    JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _6144) = new_LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initWithInt_withNSString_withNSString_withNSString_withInt_(6144, @"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF", @"2", JreEnumConstantName(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_class_(), 4), 4);
    JreEnum(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, _8192) = new_LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initWithInt_withNSString_withNSString_withNSString_withInt_(8192, @"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF", @"2", JreEnumConstantName(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_class_(), 5), 5);
    J2OBJC_SET_INITIALIZED(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength)
  }
}

@end

void LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initWithInt_withNSString_withNSString_withNSString_withInt_(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *self, jint length, NSString *p, NSString *g, NSString *__name, jint __ordinal) {
  JavaLangEnum_initWithNSString_withInt_(self, __name, __ordinal);
  self->length_ = length;
  self->p_ = new_JavaMathBigInteger_initWithNSString_withInt_(p, 16);
  self->g_ = new_JavaMathBigInteger_initWithNSString_withInt_(g, 16);
}

LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *new_LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initWithInt_withNSString_withNSString_withNSString_withInt_(jint length, NSString *p, NSString *g, NSString *__name, jint __ordinal) {
  J2OBJC_NEW_IMPL(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength, initWithInt_withNSString_withNSString_withNSString_withInt_, length, p, g, __name, __ordinal)
}

IOSObjectArray *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_values() {
  LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initialize();
  return [IOSObjectArray arrayWithObjects:LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_values_ count:6 type:LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_class_()];
}

LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_valueOfWithNSString_(NSString *name) {
  LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initialize();
  for (int i = 0; i < 6; i++) {
    LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *e = LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_values_[i];
    if ([name isEqual:[e name]]) {
      return e;
    }
  }
  @throw create_JavaLangIllegalArgumentException_initWithNSString_(name);
  return nil;
}

LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength *LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_fromOrdinal(NSUInteger ordinal) {
  LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_initialize();
  if (ordinal >= 6) {
    return nil;
  }
  return LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength_values_[ordinal];
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibComAfterlogicPgpKeyGenerationTypeLengthElGamalLength)
