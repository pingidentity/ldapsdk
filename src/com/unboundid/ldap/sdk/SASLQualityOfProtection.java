/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2014-2018 Ping Identity Corporation
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
  private final String qopString;



  /**
   * Creates a new SASL quality of protection value with the provided string
   * representation.
   *
   * @param  qopString  The string representation for this quality of protection
   *                    that should be used when interacting with the Java SASL
   *                    framework.
   */
  SASLQualityOfProtection(final String qopString)
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
  public static SASLQualityOfProtection forName(final String name)
  {
    final String lowerName = StaticUtils.toLowerCase(name.replace('_', '-'));
    for (final SASLQualityOfProtection p : values())
    {
      if (p.qopString.equals(lowerName))
      {
        return p;
      }
    }

    return null;
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
  public static List<SASLQualityOfProtection> decodeQoPList(final String s)
         throws LDAPException
  {
    final ArrayList<SASLQualityOfProtection> qopValues =
         new ArrayList<SASLQualityOfProtection>(3);
    if ((s == null) || (s.length() == 0))
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
  public static String toString(final List<SASLQualityOfProtection> qopValues)
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
