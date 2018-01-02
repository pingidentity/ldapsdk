/*
 * Copyright 2015-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that can be used
 * to consume a single-use token that was generated and provided to the user
 * through the deliver single-use token extended operation.  Once a token has
 * been consumed, it cannot be used again, although a new token can be generated
 * and delivered to the user if necessary.
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
 * This extended request has an OID of "1.3.6.1.4.1.30221.2.6.51" and it must
 * have a value with the following encoding:
 * <PRE>
 *   ConsumeSingleUseTokenRequestValue ::= SEQUENCE {
 *        userDN      LDAPDN,
 *        tokenID     OCTET STRING,
 *        tokenValue  OCTET STRING
 *        ... }
 * </PRE>
 *
 * @see  DeliverSingleUseTokenExtendedResult
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ConsumeSingleUseTokenExtendedRequest
     extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.51) for the consume single-use token
   * extended request.
   */
  public static final String CONSUME_SINGLE_USE_TOKEN_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.51";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3162206445662323272L;



  // The identifier for the token to consume.
  private final String tokenID;

  // The value for the single-use token to consume.
  private final String tokenValue;

  // The DN of the user whose account contains the token to consume.
  private final String userDN;



  /**
   * Creates a new consume single-use token extended request with the provided
   * information.
   *
   * @param  userDN      The DN of the user whose account contains the token to
   *                     consume.  It must not be {@code null}.
   * @param  tokenID     The identifier for the token to consume.  It must not
   *                     be {@code null}.
   * @param  tokenValue  The value for the single-use token to consume.  It
   *                     must not be {@code null}.
   * @param  controls    An optional set of controls to include in the request.
   *                     It may be {@code null} or empty if no controls are
   *                     required.
   */
  public ConsumeSingleUseTokenExtendedRequest(final String userDN,
                                              final String tokenID,
                                              final String tokenValue,
                                              final Control... controls)
  {
    super(CONSUME_SINGLE_USE_TOKEN_REQUEST_OID,
         encodeValue(userDN, tokenID, tokenValue),
         controls);

    this.userDN     = userDN;
    this.tokenID    = tokenID;
    this.tokenValue = tokenValue;
  }



  /**
   * Decodes the provided extended request as a consume single-use token
   * extended request.
   *
   * @param  request  The extended request to decode as a consume single-use
   *                  token extended request.
   *
   * @throws  LDAPException  If the provided extended request cannot be decoded
   *                         as a consume single-use token request.
   */
  public ConsumeSingleUseTokenExtendedRequest(final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CONSUME_SINGLE_USE_TOKEN_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      userDN = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      tokenID = ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
      tokenValue =
           ASN1OctetString.decodeAsOctetString(elements[2]).stringValue();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CONSUME_SINGLE_USE_TOKEN_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of the extended request.
   *
   * @param  userDN      The DN of the user whose account contains the token to
   *                     consume.  It must not be {@code null}.
   * @param  tokenID     The identifier for the token to consume.  It must not
   *                     be {@code null}.
   * @param  tokenValue  The value for the single-use token to consume.  It
   *                     must not be {@code null}.
   *
   * @return  An ASN.1 octet string containing the encoded value.
   */
  private static ASN1OctetString encodeValue(final String userDN,
       final String tokenID, final String tokenValue)
  {
    Validator.ensureNotNull(userDN);
    Validator.ensureNotNull(tokenID);
    Validator.ensureNotNull(tokenValue);

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1OctetString(userDN),
         new ASN1OctetString(tokenID),
         new ASN1OctetString(tokenValue));
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Retrieves the DN of the user whose account contains the token to consume.
   *
   * @return  The DN of the user whose account contains the token to consume.
   */
  public String getUserDN()
  {
    return userDN;
  }



  /**
   * Retrieves the identifier for the token to consume.
   *
   * @return  The identifier for the token to consume.
   */
  public String getTokenID()
  {
    return tokenID;
  }



  /**
   * Retrieves the value for the token to consume.
   *
   * @return  The value for the token to consume.
   */
  public String getTokenValue()
  {
    return tokenValue;
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  public ConsumeSingleUseTokenExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  public ConsumeSingleUseTokenExtendedRequest duplicate(
                                                   final Control[] controls)
  {
    final ConsumeSingleUseTokenExtendedRequest r =
         new ConsumeSingleUseTokenExtendedRequest(userDN, tokenID, tokenValue,
              controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_CONSUME_SINGLE_USE_TOKEN.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("ConsumeSingleUseTokenExtendedRequest(userDN='");
    buffer.append(userDN);
    buffer.append("', tokenID='");
    buffer.append(tokenID);
    buffer.append('\'');

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
