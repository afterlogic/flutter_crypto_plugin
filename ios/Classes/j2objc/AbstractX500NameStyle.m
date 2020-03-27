//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/x500/style/AbstractX500NameStyle.java
//

#include "ASN1Encodable.h"
#include "ASN1ObjectIdentifier.h"
#include "ASN1ParsingException.h"
#include "AbstractX500NameStyle.h"
#include "AttributeTypeAndValue.h"
#include "DERUTF8String.h"
#include "IETFUtils.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "RDN.h"
#include "X500Name.h"
#include "java/io/IOException.h"
#include "java/util/Enumeration.h"
#include "java/util/Hashtable.h"

#pragma clang diagnostic ignored "-Wprotocol"

@interface LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle ()

- (jint)calcHashCodeWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)enc;

- (jboolean)foundMatchWithBoolean:(jboolean)reverse
withLibOrgBouncycastleAsn1X500RDN:(LibOrgBouncycastleAsn1X500RDN *)rdn
withLibOrgBouncycastleAsn1X500RDNArray:(IOSObjectArray *)possRDNs;

@end

__attribute__((unused)) static jint LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_calcHashCodeWithLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle *self, id<LibOrgBouncycastleAsn1ASN1Encodable> enc);

__attribute__((unused)) static jboolean LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_foundMatchWithBoolean_withLibOrgBouncycastleAsn1X500RDN_withLibOrgBouncycastleAsn1X500RDNArray_(LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle *self, jboolean reverse, LibOrgBouncycastleAsn1X500RDN *rdn, IOSObjectArray *possRDNs);

@implementation LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

+ (JavaUtilHashtable *)copyHashTableWithJavaUtilHashtable:(JavaUtilHashtable *)paramsMap {
  return LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_copyHashTableWithJavaUtilHashtable_(paramsMap);
}

- (jint)calcHashCodeWithLibOrgBouncycastleAsn1ASN1Encodable:(id<LibOrgBouncycastleAsn1ASN1Encodable>)enc {
  return LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_calcHashCodeWithLibOrgBouncycastleAsn1ASN1Encodable_(self, enc);
}

- (jint)calculateHashCodeWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)name {
  jint hashCodeValue = 0;
  IOSObjectArray *rdns = [((LibOrgBouncycastleAsn1X500X500Name *) nil_chk(name)) getRDNs];
  for (jint i = 0; i != ((IOSObjectArray *) nil_chk(rdns))->size_; i++) {
    if ([((LibOrgBouncycastleAsn1X500RDN *) nil_chk(IOSObjectArray_Get(rdns, i))) isMultiValued]) {
      IOSObjectArray *atv = [((LibOrgBouncycastleAsn1X500RDN *) nil_chk(IOSObjectArray_Get(rdns, i))) getTypesAndValues];
      for (jint j = 0; j != ((IOSObjectArray *) nil_chk(atv))->size_; j++) {
        hashCodeValue ^= ((jint) [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X500AttributeTypeAndValue *) nil_chk(IOSObjectArray_Get(atv, j))) getType])) hash]);
        hashCodeValue ^= LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_calcHashCodeWithLibOrgBouncycastleAsn1ASN1Encodable_(self, [((LibOrgBouncycastleAsn1X500AttributeTypeAndValue *) nil_chk(IOSObjectArray_Get(atv, j))) getValue]);
      }
    }
    else {
      hashCodeValue ^= ((jint) [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X500AttributeTypeAndValue *) nil_chk([((LibOrgBouncycastleAsn1X500RDN *) nil_chk(IOSObjectArray_Get(rdns, i))) getFirst])) getType])) hash]);
      hashCodeValue ^= LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_calcHashCodeWithLibOrgBouncycastleAsn1ASN1Encodable_(self, [((LibOrgBouncycastleAsn1X500AttributeTypeAndValue *) nil_chk([((LibOrgBouncycastleAsn1X500RDN *) nil_chk(IOSObjectArray_Get(rdns, i))) getFirst])) getValue]);
    }
  }
  return hashCodeValue;
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)stringToValueWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                                                          withNSString:(NSString *)value {
  if ([((NSString *) nil_chk(value)) java_length] != 0 && [value charAtWithInt:0] == '#') {
    @try {
      return LibOrgBouncycastleAsn1X500StyleIETFUtils_valueFromHexStringWithNSString_withInt_(value, 1);
    }
    @catch (JavaIoIOException *e) {
      @throw new_LibOrgBouncycastleAsn1ASN1ParsingException_initWithNSString_(JreStrcat("$$", @"can't recode value for oid ", [((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk(oid)) getId]));
    }
  }
  if ([value java_length] != 0 && [value charAtWithInt:0] == '\\') {
    value = [value java_substring:1];
  }
  return [self encodeStringValueWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:oid withNSString:value];
}

- (id<LibOrgBouncycastleAsn1ASN1Encodable>)encodeStringValueWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:(LibOrgBouncycastleAsn1ASN1ObjectIdentifier *)oid
                                                                                              withNSString:(NSString *)value {
  return new_LibOrgBouncycastleAsn1DERUTF8String_initWithNSString_(value);
}

- (jboolean)areEqualWithLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)name1
                    withLibOrgBouncycastleAsn1X500X500Name:(LibOrgBouncycastleAsn1X500X500Name *)name2 {
  IOSObjectArray *rdns1 = [((LibOrgBouncycastleAsn1X500X500Name *) nil_chk(name1)) getRDNs];
  IOSObjectArray *rdns2 = [((LibOrgBouncycastleAsn1X500X500Name *) nil_chk(name2)) getRDNs];
  if (((IOSObjectArray *) nil_chk(rdns1))->size_ != ((IOSObjectArray *) nil_chk(rdns2))->size_) {
    return false;
  }
  jboolean reverse = false;
  if ([((LibOrgBouncycastleAsn1X500RDN *) nil_chk(IOSObjectArray_Get(rdns1, 0))) getFirst] != nil && [((LibOrgBouncycastleAsn1X500RDN *) nil_chk(IOSObjectArray_Get(rdns2, 0))) getFirst] != nil) {
    reverse = ![((LibOrgBouncycastleAsn1ASN1ObjectIdentifier *) nil_chk([((LibOrgBouncycastleAsn1X500AttributeTypeAndValue *) nil_chk([((LibOrgBouncycastleAsn1X500RDN *) nil_chk(IOSObjectArray_Get(rdns1, 0))) getFirst])) getType])) isEqual:[((LibOrgBouncycastleAsn1X500AttributeTypeAndValue *) nil_chk([((LibOrgBouncycastleAsn1X500RDN *) nil_chk(IOSObjectArray_Get(rdns2, 0))) getFirst])) getType]];
  }
  for (jint i = 0; i != rdns1->size_; i++) {
    if (!LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_foundMatchWithBoolean_withLibOrgBouncycastleAsn1X500RDN_withLibOrgBouncycastleAsn1X500RDNArray_(self, reverse, IOSObjectArray_Get(rdns1, i), rdns2)) {
      return false;
    }
  }
  return true;
}

- (jboolean)foundMatchWithBoolean:(jboolean)reverse
withLibOrgBouncycastleAsn1X500RDN:(LibOrgBouncycastleAsn1X500RDN *)rdn
withLibOrgBouncycastleAsn1X500RDNArray:(IOSObjectArray *)possRDNs {
  return LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_foundMatchWithBoolean_withLibOrgBouncycastleAsn1X500RDN_withLibOrgBouncycastleAsn1X500RDNArray_(self, reverse, rdn, possRDNs);
}

- (jboolean)rdnAreEqualWithLibOrgBouncycastleAsn1X500RDN:(LibOrgBouncycastleAsn1X500RDN *)rdn1
                       withLibOrgBouncycastleAsn1X500RDN:(LibOrgBouncycastleAsn1X500RDN *)rdn2 {
  return LibOrgBouncycastleAsn1X500StyleIETFUtils_rDNAreEqualWithLibOrgBouncycastleAsn1X500RDN_withLibOrgBouncycastleAsn1X500RDN_(rdn1, rdn2);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaUtilHashtable;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "I", 0x2, 2, 3, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 4, 5, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x1, 6, 7, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Encodable;", 0x4, 8, 7, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 9, 10, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 11, 12, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, 13, 14, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(copyHashTableWithJavaUtilHashtable:);
  methods[2].selector = @selector(calcHashCodeWithLibOrgBouncycastleAsn1ASN1Encodable:);
  methods[3].selector = @selector(calculateHashCodeWithLibOrgBouncycastleAsn1X500X500Name:);
  methods[4].selector = @selector(stringToValueWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withNSString:);
  methods[5].selector = @selector(encodeStringValueWithLibOrgBouncycastleAsn1ASN1ObjectIdentifier:withNSString:);
  methods[6].selector = @selector(areEqualWithLibOrgBouncycastleAsn1X500X500Name:withLibOrgBouncycastleAsn1X500X500Name:);
  methods[7].selector = @selector(foundMatchWithBoolean:withLibOrgBouncycastleAsn1X500RDN:withLibOrgBouncycastleAsn1X500RDNArray:);
  methods[8].selector = @selector(rdnAreEqualWithLibOrgBouncycastleAsn1X500RDN:withLibOrgBouncycastleAsn1X500RDN:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "copyHashTable", "LJavaUtilHashtable;", "calcHashCode", "LLibOrgBouncycastleAsn1ASN1Encodable;", "calculateHashCode", "LLibOrgBouncycastleAsn1X500X500Name;", "stringToValue", "LLibOrgBouncycastleAsn1ASN1ObjectIdentifier;LNSString;", "encodeStringValue", "areEqual", "LLibOrgBouncycastleAsn1X500X500Name;LLibOrgBouncycastleAsn1X500X500Name;", "foundMatch", "ZLLibOrgBouncycastleAsn1X500RDN;[LLibOrgBouncycastleAsn1X500RDN;", "rdnAreEqual", "LLibOrgBouncycastleAsn1X500RDN;LLibOrgBouncycastleAsn1X500RDN;" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle = { "AbstractX500NameStyle", "lib.org.bouncycastle.asn1.x500.style", ptrTable, methods, NULL, 7, 0x401, 9, 0, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle;
}

@end

void LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_init(LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle *self) {
  NSObject_init(self);
}

JavaUtilHashtable *LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_copyHashTableWithJavaUtilHashtable_(JavaUtilHashtable *paramsMap) {
  LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_initialize();
  JavaUtilHashtable *newTable = new_JavaUtilHashtable_init();
  id<JavaUtilEnumeration> keys = [((JavaUtilHashtable *) nil_chk(paramsMap)) keys];
  while ([((id<JavaUtilEnumeration>) nil_chk(keys)) hasMoreElements]) {
    id key = [keys nextElement];
    (void) [newTable putWithId:key withId:[paramsMap getWithId:key]];
  }
  return newTable;
}

jint LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_calcHashCodeWithLibOrgBouncycastleAsn1ASN1Encodable_(LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle *self, id<LibOrgBouncycastleAsn1ASN1Encodable> enc) {
  NSString *value = LibOrgBouncycastleAsn1X500StyleIETFUtils_valueToStringWithLibOrgBouncycastleAsn1ASN1Encodable_(enc);
  value = LibOrgBouncycastleAsn1X500StyleIETFUtils_canonicalizeWithNSString_(value);
  return ((jint) [((NSString *) nil_chk(value)) hash]);
}

jboolean LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle_foundMatchWithBoolean_withLibOrgBouncycastleAsn1X500RDN_withLibOrgBouncycastleAsn1X500RDNArray_(LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle *self, jboolean reverse, LibOrgBouncycastleAsn1X500RDN *rdn, IOSObjectArray *possRDNs) {
  if (reverse) {
    for (jint i = ((IOSObjectArray *) nil_chk(possRDNs))->size_ - 1; i >= 0; i--) {
      if (IOSObjectArray_Get(possRDNs, i) != nil && [self rdnAreEqualWithLibOrgBouncycastleAsn1X500RDN:rdn withLibOrgBouncycastleAsn1X500RDN:IOSObjectArray_Get(possRDNs, i)]) {
        (void) IOSObjectArray_Set(possRDNs, i, nil);
        return true;
      }
    }
  }
  else {
    for (jint i = 0; i != ((IOSObjectArray *) nil_chk(possRDNs))->size_; i++) {
      if (IOSObjectArray_Get(possRDNs, i) != nil && [self rdnAreEqualWithLibOrgBouncycastleAsn1X500RDN:rdn withLibOrgBouncycastleAsn1X500RDN:IOSObjectArray_Get(possRDNs, i)]) {
        (void) IOSObjectArray_Set(possRDNs, i, nil);
        return true;
      }
    }
  }
  return false;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1X500StyleAbstractX500NameStyle)
