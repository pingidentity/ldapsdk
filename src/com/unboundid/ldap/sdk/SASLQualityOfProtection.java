/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;

import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the set of supported SASL quality of protection values.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum SASLQualityOfProtection
{
  /**
   * The quality of protection value that indicates that only authentication is
   * to be performed, with no integrity or confidentiality protection for
   * subsequent communication.
   */
  AUTH("auth"),



  /**
   * The quality of protection value that indicates that integrity protection
   * will be provided for subsequent communication after authentication has
   * completed.  While integrity protection does not ensure that third-party
   * observers cannot decipher communication between the client and server, it
   * does ensure that the communication cannot be altered in an undetectable
   * manner.
   */
  AUTH_INT("auth-int"),



  /**
   * The quality of protection value that indicates that confidentiality
   * protection will be provided for subsequent communication after
   * authentication has completed.  This ensures that third-party observers will
   * not be able to decipher communication between the client and server (i.e.,
   * that the communication will be encrypted).
   */
  AUTH_CONF("auth-conf");



  // The string representation that should be used for this QoP when interacting
  // with the Java SASL framework.
  @NotNull private final String qopString;



  /**
   * Creates a new SASL quality of protection value with the provided string
   * representation.
   *
   * @param  qopString  The string representation for this quality of protection
   *                    that should be used when interacting with the Java SASL
   *                    framework.
   */
  SASLQualityOfProtection(@NotNull final String qopString)
  {
    this.qopString = qopString;
  }



  /**
   * Retrieves the SASL quality of protection value with the given name.
   *
   * @param  name  The name of the SASL quality of protection value to retrieve.
   *               It must not be {@code null}.
   *
   * @return  The requested SASL quality of protection value, or {@code null} if
   *          there is no value with the provided name.
   */
  @Nullable()
  public static SASLQualityOfProtection forName(@NotNull final String name)
  {
    switch (StaticUtils.toLowerCase(name))
    {
      case "auth":
        return AUTH;
      case "authint":
      case "auth-int":
      case "auth_int":
        return AUTH_INT;
      case "authconf":
      case "auth-conf":
      case "auth_conf":
        return AUTH_CONF;
      default:
        return null;
    }
  }



  /**
   * Decodes the provided string as a comma-delimited list of SASL quality of
   * protection values.
   *
   * @param  s  The string to be decoded.
   *
   * @return  The decoded list of SASL quality of protection values.  It will
   *          not be {@code null} but may be empty if the provided string was
   *          {@code null} or empty.
   *
   * @throws  LDAPException  If the provided string cannot be decoded as a valid
   *                         list of SASL quality of protection values.
   */
  @NotNull()
  public static List<SASLQualityOfProtection> decodeQoPList(
                                                   @Nullable final String s)
         throws LDAPException
  {
    final ArrayList<SASLQualityOfProtection> qopValues = new ArrayList<>(3);
    if ((s == null) || s.isEmpty())
    {
      return qopValues;
    }

    final StringTokenizer tokenizer = new StringTokenizer(s, ",");
    while (tokenizer.hasMoreTokens())
    {
      final String token = tokenizer.nextToken().trim();
      final SASLQualityOfProtection qop = forName(token);
      if (qop == null)
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             LDAPMessages.ERR_SASL_QOP_DECODE_LIST_INVALID_ELEMENT.get(
                  token, AUTH.qopString, AUTH_INT.qopString,
                  AUTH_CONF.qopString));
      }
      else
      {
        qopValues.add(qop);
      }
    }

    return qopValues;
  }



  /**
   * Retrieves a string representation of this SASL quality of protection.
   *
   * @return  A string representation of this SASL quality of protection.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return qopString;
  }



  /**
   * Retrieves a string representation of the provided list of quality of
   * protection values, as may be provided to a Java {@code SaslClient}.
   *
   * @param  qopValues  The list of values for which to create the string
   *                    representation.
   *
   * @return  A string representation of the provided list of quality of
   *          protection values, as may be provided to a Java
   *          {@code SaslClient}.
   */
  @NotNull()
  public static String toString(
              @NotNull final List<SASLQualityOfProtection> qopValues)
  {
    if ((qopValues == null) || qopValues.isEmpty())
    {
      return AUTH.qopString;
    }

    final StringBuilder buffer = new StringBuilder(23);
    final Iterator<SASLQualityOfProtection> iterator = qopValues.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next().qopString);
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }
    return buffer.toString();
  }
}
