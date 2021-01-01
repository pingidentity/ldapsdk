/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
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

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of the get effective rights request
 * control, which may be included in a search request to indicate that matching
 * entries should include information about the rights a given user may have
 * when interacting with that entry.
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
 * When the get effective rights control is included in a search request, then
 * each entry returned may include information about the rights that the
 * specified user has for that entry in the {@code aclRights} operational
 * attribute.  Note that because this is an operational attribute, it must be
 * explicitly included in the set of attributes to return.
 * <BR><BR>
 * If the {@code aclRights} attribute is included in the entry, then it will be
 * present with multiple sets of options.  In one case, it will have an option
 * of "entryLevel", which provides information about the rights that the user
 * has for the entry in general (see the {@link EntryRight} enum for a list of
 * the entry-level rights that can be held).  In all other cases, it will have
 * one option of "attributeLevel" and another option that is the name of the
 * attribute for which the set of rights is granted (see the
 * {@link AttributeRight} enum for a list of the attribute-level rights that can
 * be held).  In either case, the value will be a comma-delimited list of
 * right strings, where each right string is the name of the right followed by
 * a colon and a one to indicate that the right is granted or zero to indicate
 * that it is not granted.  The {@link EffectiveRightsEntry} class provides a
 * simple means of accessing the information encoded in the values of the
 * {@code aclRights} attribute.
 * <BR><BR>
 * This control was designed by Sun Microsystems, and it is not the same as the
 * get effective rights control referenced in the draft-ietf-ldapext-acl-model
 * Internet draft.  The value for this control should be encoded as follows:
 * <BR><BR>
 * <PRE>
 * GET_EFFECTIVE_RIGHTS := SEQUENCE {
 *   authzID     authzID,
 *   attributes  SEQUENCE OF AttributeType OPTIONAL }
 * </PRE>
 * <H2>Example</H2>
 * The following example demonstrates the use of the get effective rights
 * control to determine whether user "uid=admin,dc=example,dc=com" has the
 * ability to change the password for the user with uid "john.doe":
 * <PRE>
 * SearchRequest searchRequest = new SearchRequest("dc=example,dc=com",
 *      SearchScope.SUB, Filter.createEqualityFilter("uid", "john.doe"),
 *      "userPassword", "aclRights");
 * searchRequest.addControl(new GetEffectiveRightsRequestControl(
 *      "dn:uid=admin,dc=example,dc=com"));
 * SearchResult searchResult = connection.search(searchRequest);
 *
 * for (SearchResultEntry entry : searchResult.getSearchEntries())
 * {
 *   EffectiveRightsEntry effectiveRightsEntry =
 *        new EffectiveRightsEntry(entry);
 *   if (effectiveRightsEntry.rightsInformationAvailable())
 *   {
 *     if (effectiveRightsEntry.hasAttributeRight(AttributeRight.WRITE,
 *          "userPassword"))
 *     {
 *       // The admin user has permission to change the target user's password.
 *     }
 *     else
 *     {
 *       // The admin user does not have permission to change the target user's
 *       // password.
 *     }
 *   }
 *   else
 *   {
 *     // No effective rights information was returned.
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetEffectiveRightsRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.42.2.27.9.5.2) for the get effective rights request
   * control.
   */
  @NotNull public static final String GET_EFFECTIVE_RIGHTS_REQUEST_OID =
       "1.3.6.1.4.1.42.2.27.9.5.2";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 354733122036206073L;



  // The authorization ID of the user for which to calculate the effective
  // rights.
  @NotNull private final String authzID;

  // The names of the attribute types for which to calculate the effective
  // rights.
  @NotNull private final String[] attributes;



  /**
   * Creates a new get effective rights request control with the provided
   * information.  It will not be marked critical.
   *
   * @param  authzID     The authorization ID of the user for whom the effective
   *                     rights should be calculated.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes for which to calculate the
   *                     effective rights.
   */
  public GetEffectiveRightsRequestControl(@NotNull final String authzID,
                                          @NotNull final String... attributes)
  {
    this(false, authzID, attributes);
  }



  /**
   * Creates a new get effective rights request control with the provided
   * information.  It will not be marked critical.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  authzID     The authorization ID of the user for whom the effective
   *                     rights should be calculated.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes for which to calculate the
   *                     effective rights.
   */
  public GetEffectiveRightsRequestControl(final boolean isCritical,
                                          @NotNull final String authzID,
                                          @NotNull final String... attributes)
  {
    super(GET_EFFECTIVE_RIGHTS_REQUEST_OID, isCritical,
          encodeValue(authzID, attributes));

    this.authzID    = authzID;
    this.attributes = attributes;
  }



  /**
   * Creates a new get effective rights request control which is decoded from
   * the provided generic control.
   *
   * @param  control  The generic control to be decoded as a get effective
   *                  rights request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a get
   *                         effective rights request control.
   */
  public GetEffectiveRightsRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_GER_REQUEST_NO_VALUE.get());
    }

    final ASN1Element[] elements;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      elements = ASN1Sequence.decodeAsSequence(valueElement).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_GER_REQUEST_VALUE_NOT_SEQUENCE.get(e), e);
    }

    if ((elements.length < 1) || (elements.length > 2))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_GER_REQUEST_INVALID_ELEMENT_COUNT.get(
                                   elements.length));
    }

    authzID = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

    if (elements.length == 2)
    {
      try
      {
        final ASN1Element[] attrElements =
             ASN1Sequence.decodeAsSequence(elements[1]).elements();
        attributes = new String[attrElements.length];
        for (int i=0; i < attrElements.length; i++)
        {
          attributes[i] = ASN1OctetString.decodeAsOctetString(
                               attrElements[i]).stringValue();
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_GER_REQUEST_CANNOT_DECODE.get(e), e);
      }
    }
    else
    {
      attributes = StaticUtils.NO_STRINGS;
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this control.
   *
   * @param  authzID     The authorization ID of the user for whom the effective
   *                     rights should be calculated.  It must not be
   *                     {@code null}.
   * @param  attributes  The set of attributes for which to calculate the
   *                     effective rights.
   *
   * @return  An ASN.1 octet string containing the encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String authzID,
                      @Nullable final String[] attributes)
  {
    Validator.ensureNotNull(authzID);

    final ASN1Element[] elements;
    if ((attributes == null) || (attributes.length == 0))
    {
      elements = new ASN1Element[]
      {
        new ASN1OctetString(authzID),
        new ASN1Sequence()
      };
    }
    else
    {
      final ASN1Element[] attrElements = new ASN1Element[attributes.length];
      for (int i=0; i < attributes.length; i++)
      {
        attrElements[i] = new ASN1OctetString(attributes[i]);
      }

      elements = new ASN1Element[]
      {
        new ASN1OctetString(authzID),
        new ASN1Sequence(attrElements)
      };
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the authorization ID of the user for whom to calculate the
   * effective rights.
   *
   * @return  The authorization ID of the user for whom to calculate the
   *          effective rights.
   */
  @NotNull()
  public String getAuthzID()
  {
    return authzID;
  }



  /**
   * Retrieves the names of the attributes for which to calculate the effective
   * rights information.
   *
   * @return  The names of the attributes for which to calculate the effective
   *          rights information, or an empty array if no attribute names were
   *          specified.
   */
  @NotNull()
  public String[] getAttributes()
  {
    return attributes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GET_EFFECTIVE_RIGHTS_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetEffectiveRightsRequestControl(authzId='");
    buffer.append(authzID);
    buffer.append('\'');

    if (attributes.length > 0)
    {
      buffer.append(", attributes={");
      for (int i=0; i < attributes.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(attributes[i]);
      }
      buffer.append('}');
    }

    buffer.append(", isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
