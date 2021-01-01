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



import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides a collect support data log capture window implementation
 * that indicates that the tool should capture a specified amount of data (in
 * kilobytes) from the beginning and end of each log file when processing a
 * {@link CollectSupportDataExtendedRequest}.
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
public final class HeadAndTailSizeCollectSupportDataLogCaptureWindow
       extends CollectSupportDataLogCaptureWindow
{
  /**
   * The BER type for the element used to specify the amount of data in
   * kilobytes to capture from the beginning of each log file.
   */
  private static final byte TYPE_HEAD_SIZE_KB = (byte) 0x80;



  /**
   * The BER type for the element used to specify the amount of data in
   * kilobytes to capture from the end of each log file.
   */
  private static final byte TYPE_TAIL_SIZE_KB = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6810565494534462677L;



  // An ASN.1 element that provides an encoded representation of this head and
  // tail size collect support data log capture window.
  @NotNull private final ASN1Element encodedWindow;

  // The amount of data in kilobytes to capture from the beginning of each log
  // file.
  @Nullable private final Integer headSizeKB;

  // The amount of data in kilobytes to capture from the end of each log file.
  @Nullable private final Integer tailSizeKB;



  /**
   * Creates a new instance of this collect support data log capture window
   * object that will capture the specified amount of data from the beginning
   * and end of each log file.
   *
   * @param  headSizeKB  The amount of data in kilobytes to capture from the
   *                     beginning of each log file.  This may be {@code null}
   *                     if the server should select an appropriate value.
   * @param  tailSizeKB  The amount of data in kilobytes to capture from the end
   *                     of each log file.  This may be {@code null} if the
   *                     server should select an appropriate value.
   */
  public HeadAndTailSizeCollectSupportDataLogCaptureWindow(
              @Nullable final Integer headSizeKB,
              @Nullable final Integer tailSizeKB)
  {
    if (headSizeKB != null)
    {
      Validator.ensureTrue((headSizeKB >= 0),
           "If HeadAndTailSizeCollectSupportDataLogCaptureWindow.headSizeKB " +
                "is non-null, then it must also be non-negative.");
    }

    if (tailSizeKB != null)
    {
      Validator.ensureTrue((tailSizeKB >= 0),
           "If HeadAndTailSizeCollectSupportDataLogCaptureWindow.tailSizeKB " +
                "is non-null, then it must also be non-negative.");
    }

    this.headSizeKB = headSizeKB;
    this.tailSizeKB = tailSizeKB;

    final List<ASN1Element> elements = new ArrayList<>(2);
    if (headSizeKB != null)
    {
      elements.add(new ASN1Integer(TYPE_HEAD_SIZE_KB, headSizeKB));
    }

    if (tailSizeKB != null)
    {
      elements.add(new ASN1Integer(TYPE_TAIL_SIZE_KB, tailSizeKB));
    }

    encodedWindow = new ASN1Sequence(TYPE_HEAD_AND_TAIL_SIZE, elements);
  }



  /**
   * Retrieves the amount of data in kilobytes to capture from the beginning of
   * each log file, if specified.
   *
   * @return  The amount of data in kilobytes to capture from the beginning of
   *          each log file, or {@code null} if the server should select an
   *          appropriate value.
   */
  @Nullable()
  public Integer getHeadSizeKB()
  {
    return headSizeKB;
  }



  /**
   * Retrieves the amount of data in kilobytes to capture from the end of each
   * log file, if specified.
   *
   * @return  The amount of data in kilobytes to capture from the end of each
   *          log file, or {@code null} if the server should select an
   *          appropriate value.
   */
  @Nullable()
  public Integer getTailSizeKB()
  {
    return tailSizeKB;
  }



  /**
   * Decodes the provided ASN.1 element as a head and tail size collect support
   * data log capture window object.
   *
   * @param  e  The ASN.1 element to be decoded.  It must not be {@code null}.
   *
   * @return  The head and tail size collect support data log capture window
   *          object that was decoded.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a valid head and tail size collect support data log
   *                         capture window object.
   */
  @NotNull()
  static HeadAndTailSizeCollectSupportDataLogCaptureWindow decodeInternal(
              @NotNull final ASN1Element e)
         throws LDAPException
  {
    try
    {
      Integer headSizeKB = null;
      Integer tailSizeKB = null;
      for (final ASN1Element element :
           ASN1Sequence.decodeAsSequence(e).elements())
      {
        switch (element.getType())
        {
          case TYPE_HEAD_SIZE_KB:
            headSizeKB = ASN1Integer.decodeAsInteger(element).intValue();
            if (headSizeKB < 0)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_HT_SIZE_CSD_LOG_CAPTURE_WINDOW_INVALID_HEAD_SIZE.get(
                        headSizeKB));
            }
            break;
          case TYPE_TAIL_SIZE_KB:
            tailSizeKB = ASN1Integer.decodeAsInteger(element).intValue();
            if (tailSizeKB < 0)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_HT_SIZE_CSD_LOG_CAPTURE_WINDOW_INVALID_TAIL_SIZE.get(
                        tailSizeKB));
            }
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_HT_SIZE_CSD_LOG_CAPTURE_WINDOW_INVALID_ELEMENT_TYPE.get(
                      StaticUtils.toHex(element.getType())));
        }
      }

      return new HeadAndTailSizeCollectSupportDataLogCaptureWindow(headSizeKB,
           tailSizeKB);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception ex)
    {
      Debug.debugException(ex);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_HT_SIZE_CSD_LOG_WINDOW_CANNOT_DECODE.get(
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
    buffer.append("HeadAndTailSizeCollectSupportDataLogCaptureWindow(");

    if (headSizeKB != null)
    {
      buffer.append("headSizeKB=");
      buffer.append(headSizeKB);
    }

    if (tailSizeKB != null)
    {
      if (headSizeKB != null)
      {
        buffer.append(", ");
      }

      buffer.append("tailSizeKB=");
      buffer.append(tailSizeKB);
    }

    buffer.append(')');
  }
}
