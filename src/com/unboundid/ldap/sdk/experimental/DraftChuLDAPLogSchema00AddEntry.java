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

import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Attribute;
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
 * This class represents an entry that holds information about an add operation
 * processed by an LDAP server, as per the specification described in
 * draft-chu-ldap-logschema-00.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftChuLDAPLogSchema00AddEntry
       extends DraftChuLDAPLogSchema00Entry
{
  /**
   * The name of the attribute used to hold the attribute changes represented by
   * this add operation.
   */
  @NotNull public static final String ATTR_ATTRIBUTE_CHANGES = "reqMod";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1236828283266120444L;



  // The set of attributes included in the add request.
  @NotNull private final List<Attribute> attributes;



  /**
   * Creates a new instance of this add access log entry from the provided
   * entry.
   *
   * @param  entry  The entry used to create this add access log entry.
   *
   * @throws  LDAPException  If the provided entry cannot be decoded as a valid
   *                         add access log entry as per the specification
   *                         contained in draft-chu-ldap-logschema-00.
   */
  public DraftChuLDAPLogSchema00AddEntry(@NotNull final Entry entry)
         throws LDAPException
  {
    super(entry, OperationType.ADD);

    final byte[][] changes =
         entry.getAttributeValueByteArrays(ATTR_ATTRIBUTE_CHANGES);
    if ((changes == null) || (changes.length == 0))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_ATTRIBUTE_CHANGES));
    }

    final LinkedHashMap<String,List<Attribute>> attrMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(changes.length));
    for (final byte[] changeBytes : changes)
    {
      int colonPos = -1;
      for (int i=0; i < changeBytes.length; i++)
      {
        if (changeBytes[i] == ':')
        {
          colonPos = i;
          break;
        }
      }

      if (colonPos < 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_ADD_CHANGE_MISSING_COLON.get(entry.getDN(),
                  ATTR_ATTRIBUTE_CHANGES,
                  StaticUtils.toUTF8String(changeBytes)));
      }
      else if (colonPos == 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_ADD_CHANGE_MISSING_ATTR.get(entry.getDN(),
                  ATTR_ATTRIBUTE_CHANGES,
                  StaticUtils.toUTF8String(changeBytes)));
      }

      if ((colonPos == (changeBytes.length - 1)) ||
          (changeBytes[colonPos+1] != '+'))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_ADD_CHANGE_TYPE_NOT_PLUS.get(entry.getDN(),
                  ATTR_ATTRIBUTE_CHANGES,
                  StaticUtils.toUTF8String(changeBytes)));
      }

      if ((colonPos == (changeBytes.length - 2)) ||
          (changeBytes[colonPos+2] != ' '))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_ADD_CHANGE_NO_SPACE_AFTER_PLUS.get(
                  entry.getDN(), ATTR_ATTRIBUTE_CHANGES,
                  StaticUtils.toUTF8String(changeBytes)));
      }


      final String attrName =
           StaticUtils.toUTF8String(changeBytes, 0, colonPos);
      final String lowerName = StaticUtils.toLowerCase(attrName);

      List<Attribute> attrList = attrMap.get(lowerName);
      if (attrList == null)
      {
        attrList = new ArrayList<>(10);
        attrMap.put(lowerName, attrList);
      }

      final byte[] attrValue = new byte[changeBytes.length - colonPos - 3];
      if (attrValue.length > 0)
      {
        System.arraycopy(changeBytes, (colonPos+3), attrValue, 0,
             attrValue.length);
      }

      attrList.add(new Attribute(attrName, attrValue));
    }

    final ArrayList<Attribute> addAttributes = new ArrayList<>(attrMap.size());
    for (final List<Attribute> attrList : attrMap.values())
    {
      if (attrList.size() == 1)
      {
        addAttributes.addAll(attrList);
      }
      else
      {
        final byte[][] valueArray = new byte[attrList.size()][];
        for (int i=0; i < attrList.size(); i++)
        {
          valueArray[i] = attrList.get(i).getValueByteArray();
        }
        addAttributes.add(new Attribute(attrList.get(0).getName(), valueArray));
      }
    }

    attributes = Collections.unmodifiableList(addAttributes);
  }



  /**
   * Retrieves a list of the attributes included in the add request described
   * by this add access log entry.
   *
   * @return  A list of the attributes included in the add request described by
   *          this add access log entry.
   */
  @NotNull()
  public List<Attribute> getAddAttributes()
  {
    return attributes;
  }



  /**
   * Retrieves an {@code AddRequest} created from this add access log entry.
   *
   * @return  The {@code AddRequest} created from this add access log entry.
   */
  @NotNull()
  public AddRequest toAddRequest()
  {
    return new AddRequest(getTargetEntryDN(), attributes,
         getRequestControlArray());
  }
}
