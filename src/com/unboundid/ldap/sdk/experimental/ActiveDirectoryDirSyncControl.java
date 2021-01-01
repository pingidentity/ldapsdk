/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class provides support for a control that may be used to poll an Active
 * Directory Server for information about changes that have been processed.  Use
 * of this control is documented at
 * <A HREF="http://support.microsoft.com/kb/891995">
 * http://support.microsoft.com/kb/891995</A> and at
 * <A HREF="http://msdn.microsoft.com/en-us/library/ms677626.aspx">
 * http://msdn.microsoft.com/en-us/library/ms677626.aspx</A>.  The control OID
 * and value format are described at
 * <A HREF="http://msdn.microsoft.com/en-us/library/aa366978%28VS.85%29.aspx">
 * http://msdn.microsoft.com/en-us/library/aa366978%28VS.85%29.aspx</A> and the
 * values of the flags are documented at
 * <A HREF="http://msdn.microsoft.com/en-us/library/cc223347.aspx">
 * http://msdn.microsoft.com/en-us/library/cc223347.aspx</A>.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the process for using the DirSync control
 * to identify changes to user entries below "dc=example,dc=com":
 * <PRE>
 * // Create a search request that will be used to identify all users below
 * // "dc=example,dc=com".
 * final SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("objectClass", "User"));
 *
 * // Define the components that will be included in the DirSync request
 * // control.
 * ASN1OctetString cookie = null;
 * final int flags = ActiveDirectoryDirSyncControl.FLAG_INCREMENTAL_VALUES |
 *      ActiveDirectoryDirSyncControl.FLAG_OBJECT_SECURITY;
 *
 * // Create a loop that will be used to keep polling for changes.
 * while (keepLooping)
 * {
 *   // Update the controls that will be used for the search request.
 *   searchRequest.setControls(new ActiveDirectoryDirSyncControl(true, flags,
 *        50, cookie));
 *
 *   // Process the search and get the response control.
 *   final SearchResult searchResult = connection.search(searchRequest);
 *   ActiveDirectoryDirSyncControl dirSyncResponse =
 *        ActiveDirectoryDirSyncControl.get(searchResult);
 *   cookie = dirSyncResponse.getCookie();
 *
 *   // Process the search result entries because they represent entries that
 *   // have been created or modified.
 *   for (final SearchResultEntry updatedEntry :
 *        searchResult.getSearchEntries())
 *   {
 *     // Do something with the entry.
 *   }
 *
 *   // If the client might want to continue the search even after shutting
 *   // down and starting back up later, then persist the cookie now.
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ActiveDirectoryDirSyncControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.2.840.113556.1.4.841) for the DirSync control.
   */
  @NotNull public static final String DIRSYNC_OID = "1.2.840.113556.1.4.841";



  /**
   * The value of the flag that indicates that the client should only be allowed
   * to view objects and attributes that are otherwise accessible to the client.
   */
  public static final int FLAG_OBJECT_SECURITY = 0x0000_0001;



  /**
   * The value of the flag that indicates the server should return parent
   * objects before child objects.
   */
  public static final int FLAG_ANCESTORS_FIRST_ORDER = 0x0000_0800;



  /**
   * The value of the flag that indicates that the server should not return
   * private data in search results.
   */
  public static final int FLAG_PUBLIC_DATA_ONLY = 0x0000_2000;



  /**
   * The value of the flag that indicates that only changed values of attributes
   * should be included in search results.
   */
  public static final int FLAG_INCREMENTAL_VALUES = 0x8000_0000;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2871267685237800654L;



  // A cookie that may be used to resume a previous DirSync search.
  @Nullable private final ASN1OctetString cookie;

  // The value of the flags that should be used for DirSync operation.
  private final int flags;

  // The maximum number of attributes to return.
  private final int maxAttributeCount;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  ActiveDirectoryDirSyncControl()
  {
    this(true, 0, 0, null);
  }



  /**
   * Creates a new DirSync control with the provided information.
   *
   * @param  isCritical         Indicates whether this control should be marked
   *                            critical.
   * @param  flags              The value of the flags that should be used for
   *                            DirSync operation.  This should be zero if no
   *                            special flags or needed, or a bitwise OR of the
   *                            values of the individual flags that are desired.
   * @param  maxAttributeCount  The maximum number of attributes to return.
   * @param  cookie             A cookie that may be used to resume a previous
   *                            DirSync search.  This may be {@code null} if
   *                            no previous cookie is available.
   */
  public ActiveDirectoryDirSyncControl(final boolean isCritical,
                                       final int flags,
                                       final int maxAttributeCount,
                                       @Nullable final ASN1OctetString cookie)
  {
    super(DIRSYNC_OID, isCritical,
         encodeValue(flags, maxAttributeCount, cookie));

    this.flags = flags;
    this.maxAttributeCount = maxAttributeCount;

    if (cookie == null)
    {
      this.cookie = new ASN1OctetString();
    }
    else
    {
      this.cookie = cookie;
    }
  }



  /**
   * Creates a new DirSync control with settings decoded from the provided
   * control information.
   *
   * @param  oid         The OID of the control to be decoded.
   * @param  isCritical  The criticality of the control to be decoded.
   * @param  value       The value of the control to be decoded.
   *
   * @throws LDAPException  If a problem is encountered while attempting to
   *                         decode the control value as appropriate for a
   *                         DirSync control.
   */
  public ActiveDirectoryDirSyncControl(@NotNull final String oid,
                                       final boolean isCritical,
                                       @Nullable final ASN1OctetString value)
       throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DIRSYNC_CONTROL_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      flags = ASN1Integer.decodeAsInteger(elements[0]).intValue();
      maxAttributeCount = ASN1Integer.decodeAsInteger(elements[1]).intValue();
      cookie = ASN1OctetString.decodeAsOctetString(elements[2]);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DIRSYNC_CONTROL_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into a format appropriate for use as the
   * value of a DirSync control.
   *
   * @param  flags              The value of the flags that should be used for
   *                            DirSync operation.  This should be zero if no
   *                            special flags or needed, or a bitwise OR of the
   *                            values of the individual flags that are desired.
   * @param  maxAttributeCount  The maximum number of attributes to return.
   * @param  cookie             A cookie that may be used to resume a previous
   *                            DirSync search.  This may be {@code null} if
   *                            no previous cookie is available.
   *
   * @return  An ASN.1 octet string containing the encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(final int flags,
                                      final int maxAttributeCount,
                                      @Nullable final ASN1OctetString cookie)
  {
    final ASN1Element[] valueElements = new ASN1Element[3];
    valueElements[0] = new ASN1Integer(flags);
    valueElements[1] = new ASN1Integer(maxAttributeCount);

    if (cookie == null)
    {
      valueElements[2] = new ASN1OctetString();
    }
    else
    {
      valueElements[2] = cookie;
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ActiveDirectoryDirSyncControl decodeControl(@NotNull final String oid,
              final boolean isCritical, @Nullable final ASN1OctetString value)
          throws LDAPException
  {
    return new ActiveDirectoryDirSyncControl(oid, isCritical, value);
  }



  /**
   * Retrieves the value of the flags that should be used for DirSync operation.
   *
   * @return  The value of the flags that should be used for DirSync operation.
   */
  public int getFlags()
  {
    return flags;
  }



  /**
   * Retrieves the maximum number of attributes to return.
   *
   * @return  The maximum number of attributes to return.
   */
  public int getMaxAttributeCount()
  {
    return maxAttributeCount;
  }



  /**
   * Retrieves a cookie that may be used to resume a previous DirSync search,
   * if available.
   *
   * @return  A cookie that may be used to resume a previous DirSync search, or
   *          a zero-length cookie if there is none.
   */
  @Nullable()
  public ASN1OctetString getCookie()
  {
    return cookie;
  }



  /**
   * Extracts a DirSync response control from the provided result.
   *
   * @param  result  The result from which to retrieve the DirSync response
   *                 control.
   *
   * @return  The DirSync response control contained in the provided result, or
   *          {@code null} if the result did not include a DirSync response
   *          control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the DirSync response control contained in
   *                         the provided result.
   */
  @Nullable()
  public static ActiveDirectoryDirSyncControl get(
                     @NotNull final SearchResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(DIRSYNC_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof ActiveDirectoryDirSyncControl)
    {
      return (ActiveDirectoryDirSyncControl) c;
    }
    else
    {
      return new ActiveDirectoryDirSyncControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_DIRSYNC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ActiveDirectoryDirSyncControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", flags=");
    buffer.append(flags);
    buffer.append(", maxAttributeCount=");
    buffer.append(maxAttributeCount);
    buffer.append(", cookie=byte[");
    buffer.append(cookie.getValueLength());
    buffer.append("])");
  }
}
