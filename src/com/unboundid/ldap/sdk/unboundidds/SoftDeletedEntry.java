/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.Date;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SoftDeletedEntryAccessRequestControl;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides a data structure for representing information about a
 * soft-deleted entry, which results from a soft delete operation that has
 * caused the entry to be hidden so that it is not accessible to clients under
 * normal circumstances, rather than causing the entry to be completely removed
 * from the server.
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
 * A soft-deleted entry will have its RDN altered to include the entryUUID for
 * the original entry, will be updated to include the "ds-soft-delete-entry"
 * auxiliary object class, and will have additional metadata attributes added to
 * it which may include:
 * <UL>
 *   <LI>
 *     ds-soft-delete-from-dn -- This specifies the DN assigned to the entry
 *     before it was converted to a soft-deleted entry.
 *   </LI>
 *   <LI>
 *     ds-soft-delete-timestamp -- This specifies the time that the entry was
 *     converted to a soft-deleted entry.
 *   </LI>
 *   <LI>
 *     ds-soft-delete-requester-dn -- This specifies the DN of the user who
 *     requested the soft delete operation.
 *   </LI>
 *   <LI>
 *     ds-soft-delete-requester-ip-address -- This specifies the IP address of
 *     the client that requested the soft delete operation.
 *   </LI>
 * </UL>
 * <BR><BR>
 * Soft-deleted entries may only be retrieved by users who have the
 * soft-delete-read privilege, and then only by clients who issue a search
 * request with one or more of the following characteristics:
 * <UL>
 *   <LI>
 *     The search operation has a scope of baseObject and a base DN which
 *     specifically targets a soft-deleted entry.
 *   </LI>
 *   <LI>
 *     The search operation includes a filter with a component that will
 *     specifically match entries that have the ds-soft-delete-entry object
 *     class (e.g., "(objectClass=ds-soft-delete-entry)").
 *   </LI>
 *   <LI>
 *     The search operation includes a
 *     {@link SoftDeletedEntryAccessRequestControl}.
 *   </LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SoftDeletedEntry
       extends ReadOnlyEntry
{
  /**
   * The name of the attribute that will be included in a soft-deleted entry to
   * indicate the original DN the entry held before it was converted to a
   * soft-deleted entry.
   */
  @NotNull public static final String ATTR_SOFT_DELETE_FROM_DN =
       "ds-soft-delete-from-dn";



  /**
   * The name of the attribute that will be included in a soft-deleted entry to
   * indicate the DN of the user that requested the soft delete operation.
   */
  @NotNull public static final String ATTR_SOFT_DELETE_REQUESTER_DN =
       "ds-soft-delete-requester-dn";



  /**
   * The name of the attribute that will be included in a soft-deleted entry to
   * indicate the IP address of the client that requested the soft delete
   * operation.
   */
  @NotNull public static final String ATTR_SOFT_DELETE_REQUESTER_IP_ADDRESS =
       "ds-soft-delete-requester-ip-address";



  /**
   * The name of the attribute that will be included in a soft-deleted entry to
   * indicate the time it was converted to a soft-deleted entry.
   */
  @NotNull public static final String ATTR_SOFT_DELETE_TIMESTAMP =
       "ds-soft-delete-timestamp";



  /**
   * The name of the auxiliary object class that will be used to mark
   * soft-deleted entries.
   */
  @NotNull public static final String OC_SOFT_DELETED_ENTRY =
       "ds-soft-delete-entry";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3450703461178674797L;



  // The time the entry was converted to a soft-deleted entry.
  @Nullable private final Date softDeleteTimestamp;

  // The DN held by the entry at the time it was converted to a soft-deleted
  // entry.
  @NotNull private final String softDeleteFromDN;

  // The DN of the user that requested the soft delete operation.
  @Nullable private final String softDeleteRequesterDN;

  // The IP address of the client that requested the soft delete operation.
  @Nullable private final String softDeleteRequesterIPAddress;



  /**
   * Creates a soft-deleted entry from the provided entry.
   *
   * @param  entry  The entry to be processed as a soft-deleted entry.  It must
   *                not be {@code null}.
   *
   * @throws  LDAPException  If the provided entry does not represent a valid
   *                         soft-deleted entry.
   */
  public SoftDeletedEntry(@NotNull final Entry entry)
         throws LDAPException
  {
    super(entry);

    if (! entry.hasObjectClass(OC_SOFT_DELETED_ENTRY))
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_SOFT_DELETED_ENTRY_MISSING_OC.get(entry.getDN()));
    }

    softDeleteFromDN = entry.getAttributeValue(ATTR_SOFT_DELETE_FROM_DN);
    softDeleteTimestamp =
         entry.getAttributeValueAsDate(ATTR_SOFT_DELETE_TIMESTAMP);
    softDeleteRequesterDN =
         entry.getAttributeValue(ATTR_SOFT_DELETE_REQUESTER_DN);
    softDeleteRequesterIPAddress =
         entry.getAttributeValue(ATTR_SOFT_DELETE_REQUESTER_IP_ADDRESS);

    if (softDeleteFromDN == null)
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_SOFT_DELETED_ENTRY_MISSING_FROM_DN.get(entry.getDN()));
    }
  }



  /**
   * Retrieves the DN held by the entry at the time it was converted to a
   * soft-deleted entry.
   *
   * @return  The DN held by the entry at the time it was converted to a
   *          soft-deleted entry.
   */
  @NotNull()
  public String getSoftDeleteFromDN()
  {
    return softDeleteFromDN;
  }



  /**
   * Retrieves the time that the entry was converted to a soft-deleted entry,
   * if available.
   *
   * @return  The time that the entry was converted to a soft-deleted entry, or
   *          {@code null} if this is not available in the entry.
   */
  @Nullable()
  public Date getSoftDeleteTimestamp()
  {
    return softDeleteTimestamp;
  }



  /**
   * Retrieves the DN of the user that requested the soft delete operation,
   * if available.
   *
   * @return  The DN of the user that requested the soft delete operation, or
   *          {@code null} if this is not available in the entry.
   */
  @Nullable()
  public String getSoftDeleteRequesterDN()
  {
    return softDeleteRequesterDN;
  }



  /**
   * Retrieves the IP address of the client that requested the soft delete
   * operation, if available.
   *
   * @return  The IP address of the client that requested the soft delete
   *          operation, or {@code null} if this is not available in the entry.
   */
  @Nullable()
  public String getSoftDeleteRequesterIPAddress()
  {
    return softDeleteRequesterIPAddress;
  }



  /**
   * Retrieves a copy of the original entry as it appeared before the soft
   * delete operation was processed.  It will have its original DN and all
   * soft delete metadata attributes and auxiliary object class removed.
   *
   * @return  A copy of the original entry as it appeared before the soft delete
   *          operation was processed.
   */
  @NotNull()
  public ReadOnlyEntry getUndeletedEntry()
  {
    final Entry e = duplicate();

    e.setDN(softDeleteFromDN);

    e.removeAttributeValue("objectClass", OC_SOFT_DELETED_ENTRY);
    e.removeAttribute(ATTR_SOFT_DELETE_FROM_DN);
    e.removeAttribute(ATTR_SOFT_DELETE_TIMESTAMP);
    e.removeAttribute(ATTR_SOFT_DELETE_REQUESTER_DN);
    e.removeAttribute(ATTR_SOFT_DELETE_REQUESTER_IP_ADDRESS);

    return new ReadOnlyEntry(e);
  }



  /**
   * Indicates whether the provided entry may be parsed as a valid soft-deleted
   * entry.
   *
   * @param  entry  The entry to be examined.  It must not be {@code null}.
   *
   * @return  {@code true} if the provided entry contains at least a
   *          ds-soft-delete-entry object class and a ds-soft-delete-from-dn
   *          attribute.
   */
  public static boolean isSoftDeletedEntry(@NotNull final Entry entry)
  {
    return (entry.hasObjectClass(OC_SOFT_DELETED_ENTRY) &&
         entry.hasAttribute(ATTR_SOFT_DELETE_FROM_DN));
  }
}
