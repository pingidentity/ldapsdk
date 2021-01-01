/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class represents an entry that holds information about a delete
 * operation processed by an LDAP server, as per the specification described in
 * draft-chu-ldap-logschema-00.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftChuLDAPLogSchema00DeleteEntry
       extends DraftChuLDAPLogSchema00Entry
{
  /**
   * The name of the attribute used to hold information about attributes
   * contained in the entry that was deleted.
   */
  @NotNull public static final String ATTR_DELETED_ATTRIBUTE = "reqOld";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4326357861964770357L;



  // The list of deleted attributes, if available.
  @NotNull private final List<Attribute> deletedAttributes;



  /**
   * Creates a new instance of this delete access log entry from the provided
   * entry.
   *
   * @param  entry  The entry used to create this delete access log entry.
   *
   * @throws  LDAPException  If the provided entry cannot be decoded as a valid
   *                         delete access log entry as per the specification
   *                         contained in draft-chu-ldap-logschema-00.
   */
  public DraftChuLDAPLogSchema00DeleteEntry(@NotNull final Entry entry)
         throws LDAPException
  {
    super(entry, OperationType.DELETE);

    final byte[][] deletedAttrBytes =
         entry.getAttributeValueByteArrays(ATTR_DELETED_ATTRIBUTE);
    if ((deletedAttrBytes == null) || (deletedAttrBytes.length == 0))
    {
      deletedAttributes = Collections.emptyList();
      return;
    }

    final LinkedHashMap<String,List<Attribute>> attrMap = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(deletedAttrBytes.length));
    for (final byte[] attrBytes : deletedAttrBytes)
    {
      int colonPos = -1;
      for (int i=0; i < attrBytes.length; i++)
      {
        if (attrBytes[i] == ':')
        {
          colonPos = i;
          break;
        }
      }

      if (colonPos < 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_DELETE_OLD_ATTR_MISSING_COLON.get(
                  entry.getDN(), ATTR_DELETED_ATTRIBUTE,
                  StaticUtils.toUTF8String(attrBytes)));
      }
      else if (colonPos == 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_DELETE_OLD_ATTR_MISSING_ATTR.get(
                  entry.getDN(), ATTR_DELETED_ATTRIBUTE,
                  StaticUtils.toUTF8String(attrBytes)));
      }

      if ((colonPos == (attrBytes.length - 1)) ||
          (attrBytes[colonPos+1] != ' '))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_DELETE_OLD_ATTR_MISSING_SPACE.get(
                  entry.getDN(), ATTR_DELETED_ATTRIBUTE,
                  StaticUtils.toUTF8String(attrBytes)));
      }

      final String attrName =
           StaticUtils.toUTF8String(attrBytes, 0, colonPos);
      final String lowerName = StaticUtils.toLowerCase(attrName);

      List<Attribute> attrList = attrMap.get(lowerName);
      if (attrList == null)
      {
        attrList = new ArrayList<>(10);
        attrMap.put(lowerName, attrList);
      }

      final byte[] attrValue = new byte[attrBytes.length - colonPos - 2];
      if (attrValue.length > 0)
      {
        System.arraycopy(attrBytes, colonPos + 2, attrValue, 0,
             attrValue.length);
      }

      attrList.add(new Attribute(attrName, attrValue));
    }

    final ArrayList<Attribute> oldAttributes = new ArrayList<>(attrMap.size());
    for (final List<Attribute> attrList : attrMap.values())
    {
      if (attrList.size() == 1)
      {
        oldAttributes.addAll(attrList);
      }
      else
      {
        final byte[][] valueArray = new byte[attrList.size()][];
        for (int i=0; i < attrList.size(); i++)
        {
          valueArray[i] = attrList.get(i).getValueByteArray();
        }
        oldAttributes.add(new Attribute(attrList.get(0).getName(), valueArray));
      }
    }

    deletedAttributes = Collections.unmodifiableList(oldAttributes);
  }



  /**
   * Retrieves a list of the attributes from the entry that was deleted, if
   * available.
   *
   * @return  A list of the attributes from the entry that was deleted, or an
   *          empty list if no deleted attribute information was included in the
   *          access log entry.
   */
  @NotNull()
  public List<Attribute> getDeletedAttributes()
  {
    return deletedAttributes;
  }



  /**
   * Retrieves an {@code DeleteRequest} created from this delete access log
   * entry.
   *
   * @return  The {@code DeleteRequest} created from this delete access log
   *          entry.
   */
  @NotNull()
  public DeleteRequest toDeleteRequest()
  {
    return new DeleteRequest(getTargetEntryDN(), getRequestControlArray());
  }
}
