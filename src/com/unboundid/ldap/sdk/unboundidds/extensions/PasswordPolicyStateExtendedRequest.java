/*
 * Copyright 2008-2015 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015 UnboundID Corp.
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
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;
import static com.unboundid.util.Debug.*;



/**
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class is part of the Commercial Edition of the UnboundID
 *   LDAP SDK for Java.  It is not available for use in applications that
 *   include only the Standard Edition of the LDAP SDK, and is not supported for
 *   use in conjunction with non-UnboundID products.
 * </BLOCKQUOTE>
 * This class provides an implementation of the password policy state extended
 * request as used in the UnboundID Directory Server.  It may be used to
 * retrieve and/or alter password policy properties for a user account.  See the
 * documentation in the {@link PasswordPolicyStateOperation} class for
 * information about the types of operations that can be performed.
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the password policy state
 * extended operation to administratively disable a user's account:
 * <PRE>
 * PasswordPolicyStateOperation disableOp =
 *      PasswordPolicyStateOperation.createSetAccountDisabledStateOperation(
 *           true);
 * PasswordPolicyStateExtendedRequest pwpStateRequest =
 *      new PasswordPolicyStateExtendedRequest(
 *               "uid=john.doe,ou=People,dc=example,dc=com", disableOp);
 * PasswordPolicyStateExtendedResult pwpStateResult =
 *      (PasswordPolicyStateExtendedResult)
 *      connection.processExtendedOperation(pwpStateRequest);
 *
 * // NOTE:  The processExtendedOperation method will generally only throw an
 * // exception if a problem occurs while trying to send the request or read
 * // the response.  It will not throw an exception because of a non-success
 * // response.
 *
 * if (pwpStateResult.getResultCode() == ResultCode.SUCCESS)
 * {
 *   boolean isDisabled = pwpStateResult.getBooleanValue(
 *        PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_DISABLED_STATE);
 *   if (isDisabled)
 *   {
 *     // The user account has been disabled.
 *   }
 *   else
 *   {
 *     // The user account is not disabled.
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PasswordPolicyStateExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.1.6.1) for the password policy state extended
   * request.
   */
  public static final String PASSWORD_POLICY_STATE_REQUEST_OID =
       "1.3.6.1.4.1.30221.1.6.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1644137695182620213L;



  // The set of password policy state operations to process.
  private final PasswordPolicyStateOperation[] operations;

  // The DN of the user account on which to operate.
  private final String userDN;



  /**
   * Creates a new password policy state extended request with the provided user
   * DN and optional set of operations.
   *
   * @param  userDN      The DN of the user account on which to operate.
   * @param  operations  The set of password policy state operations to process.
   *                     If no operations are provided, then the effect will be
   *                     to retrieve the values of all available password policy
   *                     state properties.
   */
  public PasswordPolicyStateExtendedRequest(final String userDN,
              final PasswordPolicyStateOperation... operations)
  {
    this(userDN, null, operations);
  }



  /**
   * Creates a new password policy state extended request with the provided user
   * DN, optional set of operations, and optional set of controls.
   *
   * @param  userDN      The DN of the user account on which to operate.
   * @param  controls    The set of controls to include in the request.
   * @param  operations  The set of password policy state operations to process.
   *                     If no operations are provided, then the effect will be
   *                     to retrieve the values of all available password policy
   *                     state properties.
   */
  public PasswordPolicyStateExtendedRequest(final String userDN,
              final Control[] controls,
              final PasswordPolicyStateOperation... operations)
  {
    super(PASSWORD_POLICY_STATE_REQUEST_OID, encodeValue(userDN, operations),
          controls);

    this.userDN     = userDN;
    this.operations = operations;
  }



  /**
   * Creates a new password policy state extended request from the provided
   * generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          password policy state extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public PasswordPolicyStateExtendedRequest(
              final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_STATE_REQUEST_NO_VALUE.get());
    }

    final ASN1Element[] elements;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      elements = ASN1Sequence.decodeAsSequence(valueElement).elements();
    }
    catch (Exception e)
    {
      debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_STATE_REQUEST_VALUE_NOT_SEQUENCE.get(e),
                              e);
    }

    if ((elements.length < 1) || (elements.length > 2))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_STATE_REQUEST_INVALID_ELEMENT_COUNT.get(
                                   elements.length));
    }

    userDN = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

    if (elements.length == 1)
    {
      operations = new PasswordPolicyStateOperation[0];
    }
    else
    {
      try
      {
        final ASN1Element[] opElements =
             ASN1Sequence.decodeAsSequence(elements[1]).elements();
        operations = new PasswordPolicyStateOperation[opElements.length];
        for (int i=0; i < opElements.length; i++)
        {
          operations[i] = PasswordPolicyStateOperation.decode(opElements[i]);
        }
      }
      catch (Exception e)
      {
        debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_PWP_STATE_REQUEST_CANNOT_DECODE_OPS.get(e),
                                e);
      }
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string that may be
   * used as the value for this extended request.
   *
   * @param  userDN      The DN of the user account on which to operate.
   * @param  operations  The set of operations to be processed.
   *
   * @return  An ASN.1 octet string containing the encoded value.
   */
  private static ASN1OctetString encodeValue(final String userDN,
       final PasswordPolicyStateOperation[] operations)
  {
    final ASN1Element[] elements;
    if ((operations == null) || (operations.length == 0))
    {
      elements = new ASN1Element[]
      {
        new ASN1OctetString(userDN)
      };
    }
    else
    {
      final ASN1Element[] opElements = new ASN1Element[operations.length];
      for (int i=0; i < operations.length; i++)
      {
        opElements[i] = operations[i].encode();
      }

      elements = new ASN1Element[]
      {
        new ASN1OctetString(userDN),
        new ASN1Sequence(opElements)
      };
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the DN of the user account on which to operate.
   *
   * @return  The DN of the user account on which to operate.
   */
  public String getUserDN()
  {
    return userDN;
  }



  /**
   * Retrieves the set of password policy state operations to be processed.
   *
   * @return  The set of password policy state operations to be processed, or
   *          an empty list if the values of all password policy state
   *          properties should be retrieved.
   */
  public PasswordPolicyStateOperation[] getOperations()
  {
    return operations;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public PasswordPolicyStateExtendedResult
              process(final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new PasswordPolicyStateExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public PasswordPolicyStateExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public PasswordPolicyStateExtendedRequest duplicate(final Control[] controls)
  {
    final PasswordPolicyStateExtendedRequest r =
         new PasswordPolicyStateExtendedRequest(userDN, controls, operations);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_PW_POLICY_STATE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("PasswordPolicyStateExtendedRequest(userDN='");
    buffer.append(userDN);

    if (operations.length > 0)
    {
      buffer.append("', operations={");
      for (int i=0; i < operations.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        operations[i].toString(buffer);
      }
      buffer.append('}');
    }

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
