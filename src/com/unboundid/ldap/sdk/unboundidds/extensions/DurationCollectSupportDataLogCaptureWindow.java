/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Long;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides a collect support data log capture window implementation
 * that indicates that the tool should capture information for a specified
 * length of time up to the time the {@link CollectSupportDataExtendedRequest}
 * was received.
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
 *
 * @see  CollectSupportDataExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DurationCollectSupportDataLogCaptureWindow
       extends CollectSupportDataLogCaptureWindow
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6685577889240682295L;



  // An ASN.1 element that provides an encoded representation of this duration
  // collect support data log capture window.
  @NotNull private final ASN1Element encodedWindow;

  // The log duration, in milliseconds.
  private final long durationMillis;



  /**
   * Creates a new instance of this collect support data log capture window
   * object that will capture log content for the specified duration.
   *
   * @param  durationMillis  The duration of log content to capture, in
   *                         milliseconds.  It must be greater than or equal to
   *                         zero.
   */
  public DurationCollectSupportDataLogCaptureWindow(final long durationMillis)
  {
    Validator.ensureTrue((durationMillis >= 0L),
         "DurationCollectSupportDataLogCaptureWindow.durationMillis must be " +
              "greater than or equal to zero.");

    this.durationMillis = durationMillis;

    encodedWindow = new ASN1Long(TYPE_DURATION, durationMillis);
  }



  /**
   * Retrieves the duration, in milliseconds, of log content that should be
   * included in the support data archive.
   *
   * @return  The duration, in milliseconds, of log content that should be
   *          included in the support data archive.
   */
  public long getDurationMillis()
  {
    return durationMillis;
  }



  /**
   * Decodes the provided ASN.1 element as a duration collect support data log
   * capture window object.
   *
   * @param  e  The ASN.1 element to be decoded.  It must not be {@code null}.
   *
   * @return  The duration collect support data log capture window object that
   *          was decoded.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a valid duration collect support data log capture
   *                         window object.
   */
  @NotNull()
  static DurationCollectSupportDataLogCaptureWindow decodeInternal(
              @NotNull final ASN1Element e)
         throws LDAPException
  {
    try
    {
      final long durationMillis = ASN1Long.decodeAsLong(e).longValue();
      return new DurationCollectSupportDataLogCaptureWindow(durationMillis);
    }
    catch (final Exception ex)
    {
      Debug.debugException(ex);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DURATION_CSD_LOG_WINDOW_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(ex)),
           ex);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encode()
  {
    return encodedWindow;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DurationCollectSupportDataLogCaptureWindow(durationMillis=");
    buffer.append(durationMillis);
    buffer.append(')');
  }
}
