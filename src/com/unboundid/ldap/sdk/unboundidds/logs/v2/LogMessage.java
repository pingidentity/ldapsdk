/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
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
 * Copyright (C) 2022-2023 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2;



import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.unboundidds.logs.LogException;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message.
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
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public interface LogMessage
       extends Serializable
{
  /**
   * Retrieves the timestamp for this log message.
   *
   * @return  The timestamp for this log message.
   */
  @NotNull()
  Date getTimestamp();



  /**
   * Retrieves a map of the fields and their corresponding values in this
   * log message.
   *
   * @return  A map of the fields and their corresponding values in this log
   *          message.
   */
  @NotNull()
  Map<String,List<String>> getFields();



  /**
   * Retrieves the value of the specified field as a {@code Boolean} object.  If
   * the field has multiple values, the first will be returned.
   *
   * @param  logField  The field for which to retrieve the Boolean value.
   *
   * @return  The value of the specified field as a {@code Boolean} object, or
   *          {@code null} if the log message does not have the specified field.
   *
   * @throws  LogException  If the value of the specified field cannot be parsed
   *                        as a Boolean.
   */
  @Nullable()
  Boolean getBoolean(@NotNull LogField logField)
          throws LogException;



  /**
   * Retrieves the value of the specified field as a {@code Date} object decoded
   * from the generalized time format.  If the field has multiple values, the
   * first will be returned.
   *
   * @param  logField  The field for which to retrieve the timestamp value.
   *
   * @return  The value of the specified field as a {@code Date} object, or
   *          {@code null} if the log message does not have the specified field.
   *
   * @throws  LogException  If the value of the specified field cannot be parsed
   *                        as a {@code Date} in the generalized time format.
   */
  @Nullable()
  Date getGeneralizedTime(@NotNull LogField logField)
       throws LogException;



  /**
   * Retrieves the value of the specified field as a {@code Double} value.  If
   * the field has multiple values, the first will be returned.
   *
   * @param  logField  The field for which to retrieve the {@code Double} value.
   *
   * @return  The value of the specified field as a {@code Double} value, or
   *          {@code null} if the log message does not have the specified field.
   *
   * @throws  LogException  If the value of the specified field cannot be parsed
   *                        as a {@code Double}.
   */
  @Nullable()
  Double getDouble(@NotNull LogField logField)
         throws LogException;



  /**
   * Retrieves the value of the specified field as an {@code Integer} value.  If
   * the field has multiple values, the first will be returned.
   *
   * @param  logField  The field for which to retrieve the {@code Integer}
   *                   value.
   *
   * @return  The {@code Integer} value of the specified field, or {@code null}
   *          if the log message does not have the specified field.
   *
   * @throws  LogException  If the value of the specified field cannot be parsed
   *                        as an {@code Integer}.
   */
  @Nullable()
  Integer getInteger(@NotNull LogField logField)
       throws LogException;



  /**
   * Retrieves the value of the specified field as a {@code Long} value.  If the
   * field has multiple values, the first will be returned.
   *
   * @param  logField  The field for which to retrieve the {@code Long} value.
   *
   * @return  The {@code Long} value of the specified field, or {@code null}
   *          if the log message does not have the specified field.
   *
   * @throws  LogException  If the value of the specified field cannot be parsed
   *                        as a {@code Long}.
   */
  @Nullable()
  Long getLong(@NotNull LogField logField)
       throws LogException;



  /**
   * Retrieves the value of the specified field as a {@code Date} object decoded
   * from the ISO 8601 format described in RFC 3339.  If the field has multiple
   * values, the first will be returned.
   *
   * @param  logField  The field for which to retrieve the timestamp value.
   *
   * @return  The value of the specified field as a {@code Date} object, or
   *          {@code null} if the log message does not have the specified field.
   *
   * @throws  LogException  If the value of the specified field cannot be parsed
   *                        as a {@code Date} in the RFC 3339 format.
   */
  @Nullable()
  Date getRFC3339Timestamp(@NotNull LogField logField)
       throws LogException;



  /**
   * Retrieves the value of the specified field as a string.  If the field has
   * multiple values, the first will be returned.
   *
   * @param  logField  The field for which to retrieve the string value.
   *
   * @return  The value of the specified field as a string, or {@code null} if
   *          the log message does not have the specified field.
   */
  @Nullable()
  String getString(@NotNull LogField logField);



  /**
   * Retrieves a string representation of this log message.
   *
   * @return  A string representation of this log message.
   */
  @NotNull()
  String toString();
}
