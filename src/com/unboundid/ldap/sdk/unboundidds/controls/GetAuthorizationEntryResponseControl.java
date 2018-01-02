/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collection;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides an implementation of an LDAP control that may be included
 * in a bind response to provide information about the authenticated and/or
 * authorized user.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The value of this control will be encoded as follows:
 * <PRE>
 *   GetAuthorizationEntryResponse ::= SEQUENCE {
 *     isAuthenticated     [0] BOOLEAN,
 *     identitiesMatch     [1] BOOLEAN,
 *     authNEntry          [2] AuthEntry OPTIONAL,
 *     authZEntry          [3] AuthEntry OPTIONAL }
 *
 *   AuthEntry ::= SEQUENCE {
 *     authID         [0] AuthzId OPTIONAL,
 *     authDN         [1] LDAPDN,
 *     attributes     [2] PartialAttributeList }
 * </PRE>
 * <BR><BR>
 * See the documentation for the {@link GetAuthorizationEntryRequestControl}
 * class for more information and an example demonstrating the use of these
 * controls.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetAuthorizationEntryResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.6) for the get authorization entry response
   * control.
   */
  public static final String GET_AUTHORIZATION_ENTRY_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.6";



  /**
   * The BER type for the {@code isAuthenticated} element.
   */
  private static final byte TYPE_IS_AUTHENTICATED = (byte) 0x80;



  /**
   * The BER type for the {@code identitiesMatch} element.
   */
  private static final byte TYPE_IDENTITIES_MATCH = (byte) 0x81;



  /**
   * The BER type for the {@code authNEntry} element.
   */
  private static final byte TYPE_AUTHN_ENTRY = (byte) 0xA2;



  /**
   * The BER type for the {@code authZEntry} element.
   */
  private static final byte TYPE_AUTHZ_ENTRY = (byte) 0xA3;



  /**
   * The BER type for the {@code authID} element.
   */
  private static final byte TYPE_AUTHID = (byte) 0x80;



  /**
   * The BER type for the {@code authDN} element.
   */
  private static final byte TYPE_AUTHDN = (byte) 0x81;



  /**
   * The BER type for the {@code attributesDN} element.
   */
  private static final byte TYPE_ATTRIBUTES= (byte) 0xA2;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5443107150740697226L;



  // Indicates whether the authentication and authorization identities are the
  // same.
  private final boolean identitiesMatch;

  // Indicates whether the client is authenticated.
  private final boolean isAuthenticated;

  // The entry for the authentication identity, if available.
  private final ReadOnlyEntry authNEntry;

  // The entry for the authorization identity, if available.
  private final ReadOnlyEntry authZEntry;

  // The authID for the authentication identity, if available.
  private final String authNID;

  // The authID for the authorization identity, if available.
  private final String authZID;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  GetAuthorizationEntryResponseControl()
  {
    isAuthenticated = false;
    identitiesMatch = true;
    authNEntry      = null;
    authNID         = null;
    authZEntry      = null;
    authZID         = null;
  }



  /**
   * Creates a new get authorization entry response control with the provided
   * information.
   *
   * @param  isAuthenticated  Indicates whether the client is authenticated.
   * @param  identitiesMatch  Indicates whether the authentication identity is
   *                          the same as the authorization identity.
   * @param  authNID          The string that may be used to reference the
   *                          authentication identity.  It may be {@code null}
   *                          if information about the authentication identity
   *                          is not to be included, or if the identifier should
   *                          be derived from the DN.
   * @param  authNEntry       The entry for the authentication identity.  It may
   *                          be {@code null} if the information about the
   *                          authentication identity is not to be included.
   * @param  authZID          The string that may be used to reference the
   *                          authorization identity.  It may be {@code null}
   *                          if information about the authentication identity
   *                          is not to be included, if the identifier should
   *                          be derived from the DN, or if the authentication
   *                          and authorization identities are the same.
   * @param  authZEntry       The entry for the authentication identity.  It may
   *                          be {@code null} if the information about the
   *                          authentication identity is not to be included, or
   *                          if the authentication and authorization identities
   *                          are the same.
   */
  public GetAuthorizationEntryResponseControl(final boolean isAuthenticated,
              final boolean identitiesMatch, final String authNID,
              final ReadOnlyEntry authNEntry, final String authZID,
              final ReadOnlyEntry authZEntry)
  {
    super(GET_AUTHORIZATION_ENTRY_RESPONSE_OID, false,
          encodeValue(isAuthenticated, identitiesMatch, authNID, authNEntry,
                      authZID, authZEntry));

    this.isAuthenticated = isAuthenticated;
    this.identitiesMatch = identitiesMatch;
    this.authNID         = authNID;
    this.authNEntry      = authNEntry;
    this.authZID         = authZID;
    this.authZEntry      = authZEntry;
  }



  /**
   * Creates a new get authorization entry response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a get
   *                         authorization entry response control.
   */
  public GetAuthorizationEntryResponseControl(final String oid,
                                              final boolean isCritical,
                                              final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical,  value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_AUTHORIZATION_ENTRY_RESPONSE_NO_VALUE.get());
    }

    try
    {
      boolean       isAuth   = false;
      boolean       idsMatch = false;
      String        nID      = null;
      String        zID      = null;
      ReadOnlyEntry nEntry   = null;
      ReadOnlyEntry zEntry   = null;

      final ASN1Element valElement = ASN1Element.decode(value.getValue());
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(valElement).elements())
      {
        switch (e.getType())
        {
          case TYPE_IS_AUTHENTICATED:
            isAuth = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_IDENTITIES_MATCH:
            idsMatch = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_AUTHN_ENTRY:
            final Object[] nObjects = decodeAuthEntry(e);
            nID = (String) nObjects[0];
            nEntry = (ReadOnlyEntry) nObjects[1];
            break;
          case TYPE_AUTHZ_ENTRY:
            final Object[] zObjects = decodeAuthEntry(e);
            zID = (String) zObjects[0];
            zEntry = (ReadOnlyEntry) zObjects[1];
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GET_AUTHORIZATION_ENTRY_RESPONSE_INVALID_VALUE_TYPE.get(
                      toHex(e.getType())));
        }
      }

      isAuthenticated = isAuth;
      identitiesMatch = idsMatch;
      authNID         = nID;
      authNEntry      = nEntry;
      authZID         = zID;
      authZEntry      = zEntry;
    }
    catch (final Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_AUTHORIZATION_ENTRY_RESPONSE_CANNOT_DECODE_VALUE.get(
                getExceptionMessage(e)), e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public GetAuthorizationEntryResponseControl decodeControl(final String oid,
                                                   final boolean isCritical,
                                                   final ASN1OctetString value)
         throws LDAPException
  {
    return new GetAuthorizationEntryResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a get authorization entry response control from the provided
   * result.
   *
   * @param  result  The result from which to retrieve the get authorization
   *                 entry response control.
   *
   * @return  The get authorization entry response control contained in the
   *          provided result, or {@code null} if the result did not contain a
   *          get authorization entry response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the get authorization entry response control
   *                         contained in the provided result.
   */
  public static GetAuthorizationEntryResponseControl
                     get(final BindResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(GET_AUTHORIZATION_ENTRY_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GetAuthorizationEntryResponseControl)
    {
      return (GetAuthorizationEntryResponseControl) c;
    }
    else
    {
      return new GetAuthorizationEntryResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  /**
   * Encodes the provided information appropriately for use as the value of this
   * control.
   *
   * @param  isAuthenticated  Indicates whether the client is authenticated.
   * @param  identitiesMatch  Indicates whether the authentication identity is
   *                          the same as the authorization identity.
   * @param  authNID          The string that may be used to reference the
   *                          authentication identity.  It may be {@code null}
   *                          if information about the authentication identity
   *                          is not to be included, or if the identifier should
   *                          be derived from the DN.
   * @param  authNEntry       The entry for the authentication identity.  It may
   *                          be {@code null} if the information about the
   *                          authentication identity is not to be included.
   * @param  authZID          The string that may be used to reference the
   *                          authorization identity.  It may be {@code null}
   *                          if information about the authentication identity
   *                          is not to be included, if the identifier should
   *                          be derived from the DN, or if the authentication
   *                          and authorization identities are the same.
   * @param  authZEntry       The entry for the authentication identity.  It may
   *                          be {@code null} if the information about the
   *                          authentication identity is not to be included, or
   *                          if the authentication and authorization identities
   *                          are the same.
   *
   * @return  The ASN.1 octet string suitable for use as the control value.
   */
  private static ASN1OctetString encodeValue(final boolean isAuthenticated,
                                             final boolean identitiesMatch,
                                             final String authNID,
                                             final ReadOnlyEntry authNEntry,
                                             final String authZID,
                                             final ReadOnlyEntry authZEntry)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(4);
    elements.add(new ASN1Boolean(TYPE_IS_AUTHENTICATED, isAuthenticated));
    elements.add(new ASN1Boolean(TYPE_IDENTITIES_MATCH, identitiesMatch));

    if (authNEntry != null)
    {
      elements.add(encodeAuthEntry(TYPE_AUTHN_ENTRY, authNID, authNEntry));
    }

    if (authZEntry != null)
    {
      elements.add(encodeAuthEntry(TYPE_AUTHZ_ENTRY, authZID, authZEntry));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Encodes the provided information as appropriate for an auth entry.
   *
   * @param  type       The BER type to use for the element.
   * @param  authID     The authID to be encoded, if available.
   * @param  authEntry  The entry to be encoded.
   *
   * @return  The ASN.1 sequence containing the encoded auth entry.
   */
  private static ASN1Sequence encodeAuthEntry(final byte type,
                                              final String authID,
                                              final ReadOnlyEntry authEntry)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(3);

    if (authID != null)
    {
      elements.add(new ASN1OctetString(TYPE_AUTHID, authID));
    }

    elements.add(new ASN1OctetString(TYPE_AUTHDN, authEntry.getDN()));

    final Collection<Attribute> attributes = authEntry.getAttributes();
    final ArrayList<ASN1Element> attrElements =
         new ArrayList<ASN1Element>(attributes.size());
    for (final Attribute a : attributes)
    {
      attrElements.add(a.encode());
    }
    elements.add(new ASN1Sequence(TYPE_ATTRIBUTES, attrElements));

    return new ASN1Sequence(type, elements);
  }



  /**
   * Decodes the provided ASN.1 element into an array of auth entry elements.
   * The first element of the array will be the auth ID, and the second element
   * will be the read-only entry.
   *
   * @param  element  The element to decode.
   *
   * @return  The decoded array of elements.
   *
   * @throws  ASN1Exception  If a problem occurs while performing ASN.1 parsing.
   *
   * @throws  LDAPException  If a problem occurs while performing LDAP parsing.
   */
  private static Object[] decodeAuthEntry(final ASN1Element element)
          throws ASN1Exception, LDAPException
  {
    String authID = null;
    String authDN = null;
    final ArrayList<Attribute> attrs = new ArrayList<Attribute>();

    for (final ASN1Element e :
         ASN1Sequence.decodeAsSequence(element).elements())
    {
      switch (e.getType())
      {
        case TYPE_AUTHID:
          authID = ASN1OctetString.decodeAsOctetString(e).stringValue();
          break;
        case TYPE_AUTHDN:
          authDN = ASN1OctetString.decodeAsOctetString(e).stringValue();
          break;
        case TYPE_ATTRIBUTES:
          for (final ASN1Element ae :
               ASN1Sequence.decodeAsSequence(e).elements())
          {
            attrs.add(Attribute.decode(ASN1Sequence.decodeAsSequence(ae)));
          }
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_GET_AUTHORIZATION_ENTRY_RESPONSE_INVALID_ENTRY_TYPE.get(
                    toHex(e.getType())));
      }
    }

    return new Object[] { authID, new ReadOnlyEntry(authDN, attrs) };
  }



  /**
   * Indicates whether the client is authenticated.
   *
   * @return  {@code true} if the client is authenticated, or {@code false} if
   *          not.
   */
  public boolean isAuthenticated()
  {
    return isAuthenticated;
  }



  /**
   * Indicates whether the authentication identity and the authorization
   * identity reference the same user.
   *
   * @return  {@code true} if both the authentication identity and the
   *          authorization identity reference the same user, or {@code false}
   *          if not.
   */
  public boolean identitiesMatch()
  {
    return identitiesMatch;
  }



  /**
   * Retrieves the identifier that may be used to reference the authentication
   * identity in the directory server, if it is available.
   *
   * @return  The identifier that may be used to reference the authentication
   *          identity in the directory server, or {@code null} if it is not
   *          available.
   */
  public String getAuthNID()
  {
    if ((authNID == null) && identitiesMatch)
    {
      return authZID;
    }

    return authNID;
  }



  /**
   * Retrieves the entry for the user specified as the authentication identity,
   * if it is available.
   *
   * @return  The entry for the user specified as the authentication identity,
   *          or {@code null} if it is not available.
   */
  public ReadOnlyEntry getAuthNEntry()
  {
    if ((authNEntry == null) && identitiesMatch)
    {
      return authZEntry;
    }

    return authNEntry;
  }



  /**
   * Retrieves the identifier that may be used to reference the authorization
   * identity in the directory server, if it is available.
   *
   * @return  The identifier that may be used to reference the authorization
   *          identity in the directory server, or {@code null} if it is not
   *          available.
   */
  public String getAuthZID()
  {
    if ((authZID == null) && identitiesMatch)
    {
      return authNID;
    }

    return authZID;
  }



  /**
   * Retrieves the entry for the user specified as the authorization identity,
   * if it is available.
   *
   * @return  The entry for the user specified as the authorization identity,
   *          or {@code null} if it is not available.
   */
  public ReadOnlyEntry getAuthZEntry()
  {
    if ((authZEntry == null) && identitiesMatch)
    {
      return authNEntry;
    }

    return authZEntry;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GET_AUTHORIZATION_ENTRY_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("GetAuthorizationEntryResponseControl(identitiesMatch=");
    buffer.append(identitiesMatch);

    if (authNID != null)
    {
      buffer.append(", authNID='");
      buffer.append(authNID);
      buffer.append('\'');
    }

    if (authNEntry != null)
    {
      buffer.append(", authNEntry=");
      authNEntry.toString(buffer);
    }

    if (authZID != null)
    {
      buffer.append(", authZID='");
      buffer.append(authZID);
      buffer.append('\'');
    }

    if (authZEntry != null)
    {
      buffer.append(", authZEntry=");
      authZEntry.toString(buffer);
    }

    buffer.append(')');
  }
}
