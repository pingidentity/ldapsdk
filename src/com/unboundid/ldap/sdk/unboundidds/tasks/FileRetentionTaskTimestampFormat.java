/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2018-2021 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.ldap.sdk.unboundidds.tasks;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of allowed timestamp formats for use in conjunction
 * with the file retention task.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum FileRetentionTaskTimestampFormat
{
  /**
   * The timestamp format that uses the generalized time format in the UTC time
   * zone (with the 'Z' time zone indicator) with millisecond-level precision
   * (e.g., "20180102123456.789Z").
   */
  GENERALIZED_TIME_UTC_WITH_MILLISECONDS(true, "yyyyMMddHHmmss.SSS'Z'",
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_BEGIN_CAPTURE_GROUP +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_YEAR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MONTH +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_DAY +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_HOUR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MINUTE +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_SECOND +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MILLISECOND +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_LITERAL_Z +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_END_CAPTURE_GROUP),



  /**
   * The timestamp format that uses the generalized time format in the UTC time
   * zone (with the 'Z' time zone indicator) with second-level precision (e.g.,
   * "20180102123456Z").
   */
  GENERALIZED_TIME_UTC_WITH_SECONDS(true, "yyyyMMddHHmmss'Z'",
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_BEGIN_CAPTURE_GROUP +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_YEAR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MONTH +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_DAY +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_HOUR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MINUTE +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_SECOND +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_LITERAL_Z +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_END_CAPTURE_GROUP),



  /**
   * The timestamp format that uses the generalized time format in the UTC time
   * zone (with the 'Z' time zone indicator) with minute-level precision (e.g.,
   * "201801021234Z").
   */
  GENERALIZED_TIME_UTC_WITH_MINUTES(true, "yyyyMMddHHmm'Z'",
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_BEGIN_CAPTURE_GROUP +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_YEAR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MONTH +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_DAY +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_HOUR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MINUTE +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_LITERAL_Z +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_END_CAPTURE_GROUP),



  /**
   * The timestamp format that uses a numeric form at in the local time zone
   * (with no time zone indicator) with millisecond-level precision (e.g.,
   * "20180102123456.789").
   */
  LOCAL_TIME_WITH_MILLISECONDS(false, "yyyyMMddHHmmss.SSS",
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_BEGIN_CAPTURE_GROUP +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_YEAR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MONTH +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_DAY +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_HOUR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MINUTE +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_SECOND +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MILLISECOND +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_END_CAPTURE_GROUP),



  /**
   * The timestamp format that uses a numeric form at in the local time zone
   * (with no time zone indicator) with second-level precision (e.g.,
   * "20180102123456").
   */
  LOCAL_TIME_WITH_SECONDS(false, "yyyyMMddHHmmss",
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_BEGIN_CAPTURE_GROUP +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_YEAR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MONTH +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_DAY +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_HOUR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MINUTE +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_SECOND +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_END_CAPTURE_GROUP),



  /**
   * The timestamp format that uses a numeric form at in the local time zone
   * (with no time zone indicator) with minute-level precision (e.g.,
   * "201801021234").
   */
  LOCAL_TIME_WITH_MINUTES(false, "yyyyMMddHHmm",
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_BEGIN_CAPTURE_GROUP +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_YEAR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MONTH +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_DAY +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_HOUR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MINUTE +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_END_CAPTURE_GROUP),



  /**
   * The timestamp format that uses a numeric form at in the local time zone
   * (with no time zone indicator) with day-level precision (e.g., "20180102").
   */
  LOCAL_DATE(false, "yyyyMMdd",
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_BEGIN_CAPTURE_GROUP +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_YEAR +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_MONTH +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_DAY +
       FileRetentionTaskTimestampFormat.REGEX_FRAGMENT_END_CAPTURE_GROUP);



  /**
   * A regular expression fragment that begins a capture group.
   */
  @NotNull private static final String REGEX_FRAGMENT_BEGIN_CAPTURE_GROUP = "(";



  /**
   * A regular expression fragment that matches a year between 1900 and 2199.
   */
  @NotNull private static final String REGEX_FRAGMENT_YEAR =
       "(19|20|21)[0-9][0-9]";



  /**
   * A regular expression fragment that matches a month between 01 and 12.
   */
  @NotNull private static final String REGEX_FRAGMENT_MONTH = "(0[1-9]|1[0-2])";



  /**
   * A regular expression fragment that matches a day between 01 and 31.
   */
  @NotNull private static final String REGEX_FRAGMENT_DAY =
       "(0[1-9]|[1-2][0-9]|3[0-1])";



  /**
   * A regular expression fragment that matches an hour between 00 and 23.
   */
  @NotNull private static final String REGEX_FRAGMENT_HOUR =
       "([0-1][0-9]|2[0-3])";



  /**
   * A regular expression fragment that matches a minute between 00 and 59.
   */
  @NotNull private static final String REGEX_FRAGMENT_MINUTE = "[0-5][0-9]";



  /**
   * A regular expression fragment that matches a second between 00 and 59.
   */
  @NotNull private static final String REGEX_FRAGMENT_SECOND = "[0-5][0-9]";



  /**
   * A regular expression fragment that matches a millisecond between 000 and
   * 999, preceded by a literal period character.
   */
  @NotNull private static final String REGEX_FRAGMENT_MILLISECOND =
       "\\.[0-9][0-9][0-9]";



  /**
   * A regular expression fragment that matches a literal 'Z' character (to
   * serve as a time zone indicator).
   */
  @NotNull private static final String REGEX_FRAGMENT_LITERAL_Z = "Z";



  /**
   * A regular expression fragment that ends a capture group.
   */
  @NotNull private static final String REGEX_FRAGMENT_END_CAPTURE_GROUP = ")";



  // Indicates whether this timestamp format should use the UTC time zone rather
  // than the JVM's default time zone.
  private final boolean isInUTCTimeZone;

  // A format string that can be used to create a SimpleDateFormat object
  // capable of parsing timestamps in this format.
  @NotNull private final String simpleDateFormatString;

  // A regular expression string that can be used to match timestamps in this
  // format.
  @NotNull private final String regexString;



  /**
   * Creates a new timestamp format value with the provided information.
   *
   * @param  isInUTCTimeZone         Indicates whether the timestamp format
   *                                 should use the UTC time zone rather than
   *                                 the JVM's default time zone.
   * @param  simpleDateFormatString  A format string that can be used to create
   *                                 a {@code SimpleDateFormat] object capable
   *                                 of parsing timestamps in this format.  It
   *                                 must not be {@code null}.
   * @param  regexString             A regular expression string that can be
   *                                 used to match timestamps in this format.
   *                                 It must not be {@code null}.
   */
  FileRetentionTaskTimestampFormat(final boolean isInUTCTimeZone,
                                   @NotNull final String simpleDateFormatString,
                                   @NotNull final String regexString)
  {
    this.isInUTCTimeZone = isInUTCTimeZone;
    this.simpleDateFormatString = simpleDateFormatString;
    this.regexString = regexString;
  }



  /**
   * Indicates whether the timestamp format should use the UTC time zone rather
   * than the JVM's default time zone.
   *
   * @return  {@code true} if the timestamp format should use the UTC time zone,
   *          or {@code false} if it should use the JVM's default time zone
   *          (which itself may or may not be the UTC time zone).
   */
  public boolean isInUTCTimeZone()
  {
    return isInUTCTimeZone;
  }



  /**
   * Retrieves a format string that can be used to create a
   * {@code SimpleDateFormat} object capable of parsing timestamps in this
   * format.
   *
   * @return  A format string that can be used to create a
   *          {@code SimpleDateFormat} object capable of parsing timestamps in
   *          this format.
   */
  @NotNull()
  public String getSimpleDateFormatString()
  {
    return simpleDateFormatString;
  }



  /**
   * Retrieves a regular expression string that can be used to match timestamps
   * in this format.  The returned string will be surrounded by parentheses so
   * that it can act as a capture group.
   *
   * @return  A regular expression string that can be used to match timestamps
   *          in this format.
   */
  @NotNull()
  public String getRegexString()
  {
    return regexString;
  }



  /**
   * Retrieves the timestamp format value with the specified name.
   *
   * @param  name  The name of the timestamp format value to retrieve.
   *
   * @return  The timestamp format value with the specified name, or
   *          {@code null} if there is no value with that name.
   */
  @Nullable()
  public static FileRetentionTaskTimestampFormat forName(
                     @NotNull final String name)
  {
    final String upperName = StaticUtils.toUpperCase(name).replace('-', '_');
    for (final FileRetentionTaskTimestampFormat f : values())
    {
      if (f.name().equals(upperName))
      {
        return f;
      }
    }

    return null;
  }
}
