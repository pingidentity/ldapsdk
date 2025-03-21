/*
 * Copyright 2020-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2025 Ping Identity Corporation
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
 * Copyright (C) 2020-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.OutputStream;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPRuntimeException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides an {@link LDAPResultWriter} instance that simply prints
 * the values of all attributes in the entries that are returned, with each
 * value on a line by itself.  Entry DNs will not be included, and there will
 * not be any blank lines between entries.
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
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ValuesOnlyLDAPResultWriter
       extends LDAPResultWriter
{
  /**
   * Creates a new instance of this LDAP result writer.
   *
   * @param  outputStream  The output stream to which the output will be
   *                       written.
   */
  public ValuesOnlyLDAPResultWriter(@NotNull final OutputStream outputStream)
  {
    super(outputStream);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeComment(@NotNull final String comment)
  {
    // Comments will not be written in this format.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeHeader()
  {
    // No header is required for this format.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeSearchResultEntry(@NotNull final SearchResultEntry entry)
  {
    try
    {
      for (final Attribute a : entry.getAttributes())
      {
        for (final byte[] value : a.getValueByteArrays())
        {
          getPrintStream().write(value);
          getPrintStream().write(StaticUtils.EOL_BYTES);
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPRuntimeException(new LDAPException(ResultCode.OTHER,
           ERR_VALUES_ONLY_OUTPUT_FORMAT_WRITE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeSearchResultReference(
                   @NotNull final SearchResultReference ref)
  {
    // No output is needed for search result reference messages.
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeResult(@NotNull final LDAPResult result)
  {
    getPrintStream().flush();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void writeUnsolicitedNotification(
                   @NotNull final LDAPConnection connection,
                   @NotNull final ExtendedResult notification)
  {
    getPrintStream().flush();
  }
}
