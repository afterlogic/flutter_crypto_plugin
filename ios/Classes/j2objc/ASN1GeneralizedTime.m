//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: ../android/src/main/kotlin/lib/org/bouncycastle/asn1/ASN1GeneralizedTime.java
//

#include "ASN1GeneralizedTime.h"
#include "ASN1OctetString.h"
#include "ASN1OutputStream.h"
#include "ASN1Primitive.h"
#include "ASN1TaggedObject.h"
#include "Arrays.h"
#include "BERTags.h"
#include "DERGeneralizedTime.h"
#include "DateUtil.h"
#include "IOSClass.h"
#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "StreamUtil.h"
#include "Strings.h"
#include "java/lang/Exception.h"
#include "java/lang/IllegalArgumentException.h"
#include "java/lang/Integer.h"
#include "java/text/ParseException.h"
#include "java/text/SimpleDateFormat.h"
#include "java/util/Date.h"
#include "java/util/Locale.h"
#include "java/util/SimpleTimeZone.h"
#include "java/util/TimeZone.h"

@interface LibOrgBouncycastleAsn1ASN1GeneralizedTime ()

- (NSString *)calculateGMTOffset;

- (NSString *)convertWithInt:(jint)time;

- (jboolean)isDigitWithInt:(jint)pos;

@end

__attribute__((unused)) static NSString *LibOrgBouncycastleAsn1ASN1GeneralizedTime_calculateGMTOffset(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self);

__attribute__((unused)) static NSString *LibOrgBouncycastleAsn1ASN1GeneralizedTime_convertWithInt_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, jint time);

__attribute__((unused)) static jboolean LibOrgBouncycastleAsn1ASN1GeneralizedTime_isDigitWithInt_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, jint pos);

@implementation LibOrgBouncycastleAsn1ASN1GeneralizedTime

+ (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getInstanceWithId:(id)obj {
  return LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_(obj);
}

+ (LibOrgBouncycastleAsn1ASN1GeneralizedTime *)getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:(LibOrgBouncycastleAsn1ASN1TaggedObject *)obj
                                                                                         withBoolean:(jboolean)explicit_ {
  return LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(obj, explicit_);
}

- (instancetype)initWithNSString:(NSString *)time {
  LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithNSString_(self, time);
  return self;
}

- (instancetype)initWithJavaUtilDate:(JavaUtilDate *)time {
  LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(self, time);
  return self;
}

- (instancetype)initWithJavaUtilDate:(JavaUtilDate *)time
                  withJavaUtilLocale:(JavaUtilLocale *)locale {
  LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(self, time, locale);
  return self;
}

- (instancetype)initWithByteArray:(IOSByteArray *)bytes {
  LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithByteArray_(self, bytes);
  return self;
}

- (NSString *)getTimeString {
  return LibOrgBouncycastleUtilStrings_fromByteArrayWithByteArray_(time_);
}

- (NSString *)getTime {
  NSString *stime = LibOrgBouncycastleUtilStrings_fromByteArrayWithByteArray_(time_);
  if ([((NSString *) nil_chk(stime)) charAtWithInt:[stime java_length] - 1] == 'Z') {
    return JreStrcat("$$", [stime java_substring:0 endIndex:[stime java_length] - 1], @"GMT+00:00");
  }
  else {
    jint signPos = [stime java_length] - 5;
    jchar sign = [stime charAtWithInt:signPos];
    if (sign == '-' || sign == '+') {
      return JreStrcat("$$$C$", [stime java_substring:0 endIndex:signPos], @"GMT", [stime java_substring:signPos endIndex:signPos + 3], ':', [stime java_substring:signPos + 3]);
    }
    else {
      signPos = [stime java_length] - 3;
      sign = [stime charAtWithInt:signPos];
      if (sign == '-' || sign == '+') {
        return JreStrcat("$$$$", [stime java_substring:0 endIndex:signPos], @"GMT", [stime java_substring:signPos], @":00");
      }
    }
  }
  return JreStrcat("$$", stime, LibOrgBouncycastleAsn1ASN1GeneralizedTime_calculateGMTOffset(self));
}

- (NSString *)calculateGMTOffset {
  return LibOrgBouncycastleAsn1ASN1GeneralizedTime_calculateGMTOffset(self);
}

- (NSString *)convertWithInt:(jint)time {
  return LibOrgBouncycastleAsn1ASN1GeneralizedTime_convertWithInt_(self, time);
}

- (JavaUtilDate *)getDate {
  JavaTextSimpleDateFormat *dateF;
  NSString *stime = LibOrgBouncycastleUtilStrings_fromByteArrayWithByteArray_(time_);
  NSString *d = stime;
  if ([((NSString *) nil_chk(stime)) java_hasSuffix:@"Z"]) {
    if ([self hasFractionalSeconds]) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss.SSS'Z'");
    }
    else if ([self hasSeconds]) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss'Z'");
    }
    else if ([self hasMinutes]) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmm'Z'");
    }
    else {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHH'Z'");
    }
    [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  }
  else if ([stime java_indexOf:'-'] > 0 || [stime java_indexOf:'+'] > 0) {
    d = [self getTime];
    if ([self hasFractionalSeconds]) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss.SSSz");
    }
    else if ([self hasSeconds]) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmssz");
    }
    else if ([self hasMinutes]) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmz");
    }
    else {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHz");
    }
    [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  }
  else {
    if ([self hasFractionalSeconds]) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss.SSS");
    }
    else if ([self hasSeconds]) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmmss");
    }
    else if ([self hasMinutes]) {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHHmm");
    }
    else {
      dateF = new_JavaTextSimpleDateFormat_initWithNSString_(@"yyyyMMddHH");
    }
    [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, [((JavaUtilTimeZone *) nil_chk(JavaUtilTimeZone_getDefault())) getID])];
  }
  if ([self hasFractionalSeconds]) {
    NSString *frac = [((NSString *) nil_chk(d)) java_substring:14];
    jint index;
    for (index = 1; index < [((NSString *) nil_chk(frac)) java_length]; index++) {
      jchar ch = [frac charAtWithInt:index];
      if (!('0' <= ch && ch <= '9')) {
        break;
      }
    }
    if (index - 1 > 3) {
      frac = JreStrcat("$$", [frac java_substring:0 endIndex:4], [frac java_substring:index]);
      d = JreStrcat("$$", [d java_substring:0 endIndex:14], frac);
    }
    else if (index - 1 == 1) {
      frac = JreStrcat("$$$", [frac java_substring:0 endIndex:index], @"00", [frac java_substring:index]);
      d = JreStrcat("$$", [d java_substring:0 endIndex:14], frac);
    }
    else if (index - 1 == 2) {
      frac = JreStrcat("$C$", [frac java_substring:0 endIndex:index], '0', [frac java_substring:index]);
      d = JreStrcat("$$", [d java_substring:0 endIndex:14], frac);
    }
  }
  return LibOrgBouncycastleAsn1DateUtil_epochAdjustWithJavaUtilDate_([dateF parseWithNSString:d]);
}

- (jboolean)hasFractionalSeconds {
  for (jint i = 0; i != ((IOSByteArray *) nil_chk(time_))->size_; i++) {
    if (IOSByteArray_Get(time_, i) == '.') {
      if (i == 14) {
        return true;
      }
    }
  }
  return false;
}

- (jboolean)hasSeconds {
  return LibOrgBouncycastleAsn1ASN1GeneralizedTime_isDigitWithInt_(self, 12) && LibOrgBouncycastleAsn1ASN1GeneralizedTime_isDigitWithInt_(self, 13);
}

- (jboolean)hasMinutes {
  return LibOrgBouncycastleAsn1ASN1GeneralizedTime_isDigitWithInt_(self, 10) && LibOrgBouncycastleAsn1ASN1GeneralizedTime_isDigitWithInt_(self, 11);
}

- (jboolean)isDigitWithInt:(jint)pos {
  return LibOrgBouncycastleAsn1ASN1GeneralizedTime_isDigitWithInt_(self, pos);
}

- (jboolean)isConstructed {
  return false;
}

- (jint)encodedLength {
  jint length = ((IOSByteArray *) nil_chk(time_))->size_;
  return 1 + LibOrgBouncycastleAsn1StreamUtil_calculateBodyLengthWithInt_(length) + length;
}

- (void)encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:(LibOrgBouncycastleAsn1ASN1OutputStream *)outArg {
  [((LibOrgBouncycastleAsn1ASN1OutputStream *) nil_chk(outArg)) writeEncodedWithInt:LibOrgBouncycastleAsn1BERTags_GENERALIZED_TIME withByteArray:time_];
}

- (LibOrgBouncycastleAsn1ASN1Primitive *)toDERObject {
  return new_LibOrgBouncycastleAsn1DERGeneralizedTime_initWithByteArray_(time_);
}

- (jboolean)asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:(LibOrgBouncycastleAsn1ASN1Primitive *)o {
  if (!([o isKindOfClass:[LibOrgBouncycastleAsn1ASN1GeneralizedTime class]])) {
    return false;
  }
  return LibOrgBouncycastleUtilArrays_areEqualWithByteArray_withByteArray_(time_, ((LibOrgBouncycastleAsn1ASN1GeneralizedTime *) nil_chk(((LibOrgBouncycastleAsn1ASN1GeneralizedTime *) cast_chk(o, [LibOrgBouncycastleAsn1ASN1GeneralizedTime class]))))->time_);
}

- (NSUInteger)hash {
  return LibOrgBouncycastleUtilArrays_hashCodeWithByteArray_(time_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x9, 0, 1, -1, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1GeneralizedTime;", 0x9, 0, 2, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 3, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 4, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 5, -1, -1, -1, -1 },
    { NULL, NULL, 0x0, -1, 6, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x2, -1, -1, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x2, 7, 8, -1, -1, -1, -1 },
    { NULL, "LJavaUtilDate;", 0x1, -1, -1, 9, -1, -1, -1 },
    { NULL, "Z", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x2, 10, 8, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x0, 11, 12, 13, -1, -1, -1 },
    { NULL, "LLibOrgBouncycastleAsn1ASN1Primitive;", 0x0, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x0, 14, 15, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 16, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getInstanceWithId:);
  methods[1].selector = @selector(getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject:withBoolean:);
  methods[2].selector = @selector(initWithNSString:);
  methods[3].selector = @selector(initWithJavaUtilDate:);
  methods[4].selector = @selector(initWithJavaUtilDate:withJavaUtilLocale:);
  methods[5].selector = @selector(initWithByteArray:);
  methods[6].selector = @selector(getTimeString);
  methods[7].selector = @selector(getTime);
  methods[8].selector = @selector(calculateGMTOffset);
  methods[9].selector = @selector(convertWithInt:);
  methods[10].selector = @selector(getDate);
  methods[11].selector = @selector(hasFractionalSeconds);
  methods[12].selector = @selector(hasSeconds);
  methods[13].selector = @selector(hasMinutes);
  methods[14].selector = @selector(isDigitWithInt:);
  methods[15].selector = @selector(isConstructed);
  methods[16].selector = @selector(encodedLength);
  methods[17].selector = @selector(encodeWithLibOrgBouncycastleAsn1ASN1OutputStream:);
  methods[18].selector = @selector(toDERObject);
  methods[19].selector = @selector(asn1EqualsWithLibOrgBouncycastleAsn1ASN1Primitive:);
  methods[20].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "time_", "[B", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "getInstance", "LNSObject;", "LLibOrgBouncycastleAsn1ASN1TaggedObject;Z", "LNSString;", "LJavaUtilDate;", "LJavaUtilDate;LJavaUtilLocale;", "[B", "convert", "I", "LJavaTextParseException;", "isDigit", "encode", "LLibOrgBouncycastleAsn1ASN1OutputStream;", "LJavaIoIOException;", "asn1Equals", "LLibOrgBouncycastleAsn1ASN1Primitive;", "hashCode" };
  static const J2ObjcClassInfo _LibOrgBouncycastleAsn1ASN1GeneralizedTime = { "ASN1GeneralizedTime", "lib.org.bouncycastle.asn1", ptrTable, methods, fields, 7, 0x1, 21, 1, -1, -1, -1, -1, -1 };
  return &_LibOrgBouncycastleAsn1ASN1GeneralizedTime;
}

@end

LibOrgBouncycastleAsn1ASN1GeneralizedTime *LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_(id obj) {
  LibOrgBouncycastleAsn1ASN1GeneralizedTime_initialize();
  if (obj == nil || [obj isKindOfClass:[LibOrgBouncycastleAsn1ASN1GeneralizedTime class]]) {
    return (LibOrgBouncycastleAsn1ASN1GeneralizedTime *) cast_chk(obj, [LibOrgBouncycastleAsn1ASN1GeneralizedTime class]);
  }
  if ([obj isKindOfClass:[IOSByteArray class]]) {
    @try {
      return (LibOrgBouncycastleAsn1ASN1GeneralizedTime *) cast_chk(LibOrgBouncycastleAsn1ASN1Primitive_fromByteArrayWithByteArray_((IOSByteArray *) cast_chk(obj, [IOSByteArray class])), [LibOrgBouncycastleAsn1ASN1GeneralizedTime class]);
    }
    @catch (JavaLangException *e) {
      @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"encoding error in getInstance: ", [e description]));
    }
  }
  @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"illegal object in getInstance: ", [[obj java_getClass] getName]));
}

LibOrgBouncycastleAsn1ASN1GeneralizedTime *LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithLibOrgBouncycastleAsn1ASN1TaggedObject_withBoolean_(LibOrgBouncycastleAsn1ASN1TaggedObject *obj, jboolean explicit_) {
  LibOrgBouncycastleAsn1ASN1GeneralizedTime_initialize();
  LibOrgBouncycastleAsn1ASN1Primitive *o = [((LibOrgBouncycastleAsn1ASN1TaggedObject *) nil_chk(obj)) getObject];
  if (explicit_ || [o isKindOfClass:[LibOrgBouncycastleAsn1ASN1GeneralizedTime class]]) {
    return LibOrgBouncycastleAsn1ASN1GeneralizedTime_getInstanceWithId_(o);
  }
  else {
    return new_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithByteArray_([((LibOrgBouncycastleAsn1ASN1OctetString *) nil_chk(((LibOrgBouncycastleAsn1ASN1OctetString *) cast_chk(o, [LibOrgBouncycastleAsn1ASN1OctetString class])))) getOctets]);
  }
}

void LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithNSString_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, NSString *time) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  self->time_ = LibOrgBouncycastleUtilStrings_toByteArrayWithNSString_(time);
  @try {
    (void) [self getDate];
  }
  @catch (JavaTextParseException *e) {
    @throw new_JavaLangIllegalArgumentException_initWithNSString_(JreStrcat("$$", @"invalid date string: ", [e getMessage]));
  }
}

LibOrgBouncycastleAsn1ASN1GeneralizedTime *new_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithNSString_(NSString *time) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1GeneralizedTime, initWithNSString_, time)
}

LibOrgBouncycastleAsn1ASN1GeneralizedTime *create_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithNSString_(NSString *time) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1GeneralizedTime, initWithNSString_, time)
}

void LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, JavaUtilDate *time) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  JavaTextSimpleDateFormat *dateF = new_JavaTextSimpleDateFormat_initWithNSString_withJavaUtilLocale_(@"yyyyMMddHHmmss'Z'", JreLoadStatic(LibOrgBouncycastleAsn1DateUtil, EN_Locale));
  [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  self->time_ = LibOrgBouncycastleUtilStrings_toByteArrayWithNSString_([dateF formatWithJavaUtilDate:time]);
}

LibOrgBouncycastleAsn1ASN1GeneralizedTime *new_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(JavaUtilDate *time) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1GeneralizedTime, initWithJavaUtilDate_, time)
}

LibOrgBouncycastleAsn1ASN1GeneralizedTime *create_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_(JavaUtilDate *time) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1GeneralizedTime, initWithJavaUtilDate_, time)
}

void LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, JavaUtilDate *time, JavaUtilLocale *locale) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  JavaTextSimpleDateFormat *dateF = new_JavaTextSimpleDateFormat_initWithNSString_withJavaUtilLocale_(@"yyyyMMddHHmmss'Z'", locale);
  [dateF setTimeZoneWithJavaUtilTimeZone:new_JavaUtilSimpleTimeZone_initWithInt_withNSString_(0, @"Z")];
  self->time_ = LibOrgBouncycastleUtilStrings_toByteArrayWithNSString_([dateF formatWithJavaUtilDate:time]);
}

LibOrgBouncycastleAsn1ASN1GeneralizedTime *new_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1GeneralizedTime, initWithJavaUtilDate_withJavaUtilLocale_, time, locale)
}

LibOrgBouncycastleAsn1ASN1GeneralizedTime *create_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithJavaUtilDate_withJavaUtilLocale_(JavaUtilDate *time, JavaUtilLocale *locale) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1GeneralizedTime, initWithJavaUtilDate_withJavaUtilLocale_, time, locale)
}

void LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithByteArray_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, IOSByteArray *bytes) {
  LibOrgBouncycastleAsn1ASN1Primitive_init(self);
  self->time_ = bytes;
}

LibOrgBouncycastleAsn1ASN1GeneralizedTime *new_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithByteArray_(IOSByteArray *bytes) {
  J2OBJC_NEW_IMPL(LibOrgBouncycastleAsn1ASN1GeneralizedTime, initWithByteArray_, bytes)
}

LibOrgBouncycastleAsn1ASN1GeneralizedTime *create_LibOrgBouncycastleAsn1ASN1GeneralizedTime_initWithByteArray_(IOSByteArray *bytes) {
  J2OBJC_CREATE_IMPL(LibOrgBouncycastleAsn1ASN1GeneralizedTime, initWithByteArray_, bytes)
}

NSString *LibOrgBouncycastleAsn1ASN1GeneralizedTime_calculateGMTOffset(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self) {
  NSString *sign = @"+";
  JavaUtilTimeZone *timeZone = JavaUtilTimeZone_getDefault();
  jint offset = [((JavaUtilTimeZone *) nil_chk(timeZone)) getRawOffset];
  if (offset < 0) {
    sign = @"-";
    offset = -offset;
  }
  jint hours = offset / (60 * 60 * 1000);
  jint minutes = (offset - (hours * 60 * 60 * 1000)) / (60 * 1000);
  @try {
    if ([timeZone useDaylightTime] && [timeZone inDaylightTimeWithJavaUtilDate:[self getDate]]) {
      hours += [sign isEqual:@"+"] ? 1 : -1;
    }
  }
  @catch (JavaTextParseException *e) {
  }
  return JreStrcat("$$$C$", @"GMT", sign, LibOrgBouncycastleAsn1ASN1GeneralizedTime_convertWithInt_(self, hours), ':', LibOrgBouncycastleAsn1ASN1GeneralizedTime_convertWithInt_(self, minutes));
}

NSString *LibOrgBouncycastleAsn1ASN1GeneralizedTime_convertWithInt_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, jint time) {
  if (time < 10) {
    return JreStrcat("CI", '0', time);
  }
  return JavaLangInteger_toStringWithInt_(time);
}

jboolean LibOrgBouncycastleAsn1ASN1GeneralizedTime_isDigitWithInt_(LibOrgBouncycastleAsn1ASN1GeneralizedTime *self, jint pos) {
  return ((IOSByteArray *) nil_chk(self->time_))->size_ > pos && IOSByteArray_Get(self->time_, pos) >= '0' && IOSByteArray_Get(self->time_, pos) <= '9';
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(LibOrgBouncycastleAsn1ASN1GeneralizedTime)