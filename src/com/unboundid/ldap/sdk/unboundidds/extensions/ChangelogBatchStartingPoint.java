/*
 * Copyright 2010-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.Serializable;
import java.util.Date;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class defines the API that should be implemented by classes which may
 * represent a way to identify the start of a batch of changes to retrieve using
 * the {@link GetChangelogBatchExtendedRequest}.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class ChangelogBatchStartingPoint
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1580168275337643812L;



  /**
   * Encodes this starting point value to an ASN.1 element suitable for
   * inclusion in a changelog batch extended request.
   *
   * @return  The encoded representation of this starting point value.
   */
  public abstract ASN1Element encode();



  /**
   * Decodes the provided ASN.1 element as a changelog batch starting point.
   *
   * @param  element  The ASN.1 element to be decoded.  It must not be
   *                  {@code null}.
   *
   * @return  The decoded changelog batch starting point.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a changelog batch starting point.
   */
  public static ChangelogBatchStartingPoint decode(final ASN1Element element)
         throws LDAPException
  {
    Validator.ensureNotNull(element);

    switch (element.getType())
    {
      case ResumeWithTokenStartingPoint.TYPE:
        return new ResumeWithTokenStartingPoint(
             ASN1OctetString.decodeAsOctetString(element));

      case ResumeWithCSNStartingPoint.TYPE:
        return new ResumeWithCSNStartingPoint(
             ASN1OctetString.decodeAsOctetString(element).stringValue());

      case BeginningOfChangelogStartingPoint.TYPE:
        if (element.getValueLength() != 0)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_BEGINNING_OF_CHANGELOG_STARTING_POINT_HAS_VALUE.get());
        }
        return new BeginningOfChangelogStartingPoint();

      case EndOfChangelogStartingPoint.TYPE:
        if (element.getValueLength() != 0)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_END_OF_CHANGELOG_STARTING_POINT_HAS_VALUE.get());
        }
        return new EndOfChangelogStartingPoint();

      case ChangeTimeStartingPoint.TYPE:
        final Date time;
        try
        {
          time = StaticUtils.decodeGeneralizedTime(
               ASN1OctetString.decodeAsOctetString(element).stringValue());
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_CHANGE_TIME_STARTING_POINT_MALFORMED_VALUE.get(
                    StaticUtils.getExceptionMessage(e)), e);
        }
        return new ChangeTimeStartingPoint(time.getTime());

      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_UNKNOWN_CHANGELOG_BATCH_STARTING_POINT_TYPE.get(
                  StaticUtils.toHex(element.getType())));
    }
  }



  /**
   * Retrieves a string representation of this changelog batch starting point.
   *
   * @return  A string representation of this changelog batch starting point.
   */
  @Override()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this changelog batch starting point to
   * the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public abstract void toString(StringBuilder buffer);
}
