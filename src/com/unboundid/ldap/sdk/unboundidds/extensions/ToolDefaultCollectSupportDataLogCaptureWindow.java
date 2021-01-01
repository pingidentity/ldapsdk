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
import com.unboundid.asn1.ASN1Null;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides a collect support data log capture window implementation
 * that indicates that the tool should use its default logic when determining
 * which log content to include in the support data archive when processing a
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
public final class ToolDefaultCollectSupportDataLogCaptureWindow
       extends CollectSupportDataLogCaptureWindow
{
  /**
   * The singleton instance of this tool-default collect support data log
   * capture window object.
   */
  @NotNull private static final ToolDefaultCollectSupportDataLogCaptureWindow
       INSTANCE = new ToolDefaultCollectSupportDataLogCaptureWindow();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7186806291464509659L;



  // An ASN.1 element that provides an encoded representation of this
  // tool-default collect support data log capture window.
  @NotNull private final ASN1Element encodedWindow;



  /**
   * Creates a new instance of this tool-default collect support data log
   * capture window object.
   */
  private ToolDefaultCollectSupportDataLogCaptureWindow()
  {
    encodedWindow = new ASN1Null(TYPE_TOOL_DEFAULT);
  }



  /**
   * Retrieves the singleton instance of this tool-default collect support data
   * log capture window object.
   *
   * @return  The singleton instance of this tool-default collect support data
   *          log capture window object.
   */
  @NotNull()
  public static ToolDefaultCollectSupportDataLogCaptureWindow getInstance()
  {
    return INSTANCE;
  }



  /**
   * Decodes the provided ASN.1 element as a tool-default collect support data
   * log capture window object.
   *
   * @param  e  The ASN.1 element to be decoded.  It must not be {@code null}.
   *
   * @return  The tool-default collect support data log capture window object
   *          that was decoded.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a valid tool-default collect support data log
   *                         capture window object.
   */
  @NotNull()
  static ToolDefaultCollectSupportDataLogCaptureWindow decodeInternal(
              @NotNull final ASN1Element e)
         throws LDAPException
  {
    try
    {
      ASN1Null.decodeAsNull(e);
    }
    catch (final Exception ex)
    {
      Debug.debugException(ex);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_TOOL_DEFAULT_CSD_LOG_WINDOW_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(ex)),
           ex);
    }

    return INSTANCE;
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
    buffer.append("ToolDefaultCollectSupportDataLogCaptureWindow()");
  }
}
