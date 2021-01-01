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



import java.io.Serializable;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class defines an API that may be used to indicate how the tool should
 * determine which log content to include in the support data archive when
 * processing a {@link CollectSupportDataExtendedRequest}.
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
 * <BR>
 * Available log capture window implementations include:
 * <UL>
 *   <LI>
 *     {@link ToolDefaultCollectSupportDataLogCaptureWindow} -- Indicates that
 *     the tool should capture a default amount of log content to include in
 *     the support data archive.
 *   </LI>
 *   <LI>
 *     {@link DurationCollectSupportDataLogCaptureWindow} -- Indicates that the
 *     support data archive should include log messages for a specified duration
 *     leading up to the time that the
 *     {@link CollectSupportDataExtendedRequest} was received by the server.
 *   </LI>
 *   <LI>
 *     {@link TimeWindowCollectSupportDataLogCaptureWindow} -- Indicates that
 *     the support data archive should include log messages that fall between
 *     specified start and end times.
 *   </LI>
 *   <LI>
 *     {@link HeadAndTailSizeCollectSupportDataLogCaptureWindow} -- Indicates
 *     that the support data archive should include a specified amount of data
 *     from the beginning and end of each log file.
 *   </LI>
 * </UL>
 *
 * @see  CollectSupportDataExtendedRequest
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class CollectSupportDataLogCaptureWindow
       implements Serializable
{
  /**
   * The BER type that should be used for tool-default log capture window
   * objects.
   */
  protected static final byte TYPE_TOOL_DEFAULT = (byte) 0x80;



  /**
   * The BER type that should be used for duration log capture window objects.
   */
  protected static final byte TYPE_DURATION = (byte) 0x81;



  /**
   * The BER type that should be used for time window log capture window
   * objects.
   */
  protected static final byte TYPE_TIME_WINDOW = (byte) 0xA2;



  /**
   * The BER type that should be used for head and tail size log capture window
   * objects.
   */
  protected static final byte TYPE_HEAD_AND_TAIL_SIZE = (byte) 0xA3;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6491461694423982840L;



  /**
   * Decodes the provided ASN.1 element as a collect support data log capture
   * window object.
   *
   * @param  e  The ASN.1 element to be decoded as a log capture window object.
   *            It must not be {@code null}.
   *
   * @return  The collect support data log capture window object that was
   *          decoded from the provided ASN.1 element.
   *
   * @throws  LDAPException  If the provided element cannot be decoded as a
   *                         valid collect support data log capture window
   *                         object.
   */
  @NotNull()
  public static CollectSupportDataLogCaptureWindow decode(
                     @NotNull final ASN1Element e)
         throws LDAPException
  {
    switch (e.getType())
    {
      case TYPE_TOOL_DEFAULT:
        return ToolDefaultCollectSupportDataLogCaptureWindow.decodeInternal(e);
      case TYPE_DURATION:
        return DurationCollectSupportDataLogCaptureWindow.decodeInternal(e);
      case TYPE_TIME_WINDOW:
        return TimeWindowCollectSupportDataLogCaptureWindow.decodeInternal(e);
      case TYPE_HEAD_AND_TAIL_SIZE:
        return HeadAndTailSizeCollectSupportDataLogCaptureWindow.decodeInternal(
             e);
      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CSD_LOG_WINDOW_CANNOT_DECODE.get(
                  StaticUtils.toHex(e.getType())));
    }
  }



  /**
   * Encodes this collect support data log capture window object to an ASN.1
   * element.
   *
   * @return  The ASN.1 element that contains an encoded representation of this
   *          collect support data log capture window object.
   */
  @NotNull()
  public abstract ASN1Element encode();



  /**
   * Retrieves a string representation of this collect support data log capture
   * window object.
   *
   * @return  A string representation of this collect support data log capture
   *          window object.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this collect support data log capture
   * window object to the provided buffer.
   *
   * @param  buffer  The buffer to which the string representation will be
   *                 appended.  It must not be {@code null}.
   */
  public abstract void toString(@NotNull final StringBuilder buffer);
}
