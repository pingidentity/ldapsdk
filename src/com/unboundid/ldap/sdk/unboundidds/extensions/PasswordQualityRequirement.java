/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
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

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides a data structure that describes a requirement that
 * passwords must satisfy in order to be accepted by the server.
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
 * A password quality requirement will always include a description, which
 * should be a string that provides a user-friendly description of the
 * constraints that a proposed password must satisfy in order to meet this
 * requirement and be accepted by the server.  It may optionally include
 * additional information that could allow an application to attempt some kind
 * of pre-validation in order to determine whether a proposed password might
 * fall outside the constraints associated with this requirement and would
 * therefore be rejected by the server.  This could allow a client to provide
 * better performance (by not having to submit a password to the server and wait
 * for the response in order to detect certain kinds of problems) and a better
 * user experience (for example, by interactively indicating whether the value
 * is acceptable as the user is entering it).
 * <BR><BR>
 * If a password quality requirement object does provide client-side validation
 * data, then it will include at least a validation type (which indicates the
 * nature of the validation that will be performed), and an optional set of
 * properties that provide additional information about the specific nature of
 * the validation.  For example, if the server is configured with a length-based
 * password validator that requires passwords to be between eight and 20
 * characters, then the requirement may have a validation type of "length" and
 * two validation properties:  "minimum-length" with a value of "8" and
 * "maximum-length" with a value of "20".  An application that supports this
 * type of client-side validation could prevent a user from supplying a password
 * that is too short or too long without the need to communicate with the
 * server.
 * <BR><BR>
 * Note that not all types of password requirements will support client-side
 * validation.  For example, the server may be configured to use a dictionary
 * with some of the most commonly-used passwords in an attempt to prevent
 * users from selecting passwords that may be easily guessed, or the server
 * may be configured with a password history to prevent users from selecting a
 * password that they had already used.  In these kinds of cases, the
 * application will not have access to the information necessary to make the
 * determination using client-side logic.  The server is the ultimate authority
 * as to whether a proposed password will be accepted, and even applications
 * should be prepared to handle the case in which a password is rejected by the
 * server even if client-side validation does not indicate that there are any
 * problems with the password.  There may also be cases in which the reason that
 * an attempt to set a password fails for a reason that is not related to the
 * quality of the provided password.
 * <BR><BR>
 * However, even in cases where an application may not be able to perform any
 * client-side validation, the server may still offer a client-side validation
 * type and validation properties.  This is not intended to help the client
 * determine whether a proposed password is acceptable, but could allow the
 * client to convey information about the requirement to the user in a more
 * flexible manner than simply providing the requirement description (e.g., it
 * could allow the client to provide information about the requirement to the
 * user in a different language than the server-provided description, or it
 * could allow information about one requirement to be split into multiple
 * elements, or multiple requirements combined into a single element.
 * <BR><BR>
 * If it appears in an LDAP protocol element (e.g., a get password quality
 * requirements extended response, or a password validation details response
 * control), it should have the following ASN.1 encoding:
 * <PRE>
 *   PasswordQualityRequirement ::= SEQUENCE {
 *        description                  OCTET STRING,
 *        clientSideValidationInfo     [0] SEQUENCE {
 *             validationType     OCTET STRING,
 *             properties         [0] SET OF SEQUENCE {
 *                  name      OCTET STRING,
 *                  value     OCTET STRING } OPTIONAL } OPTIONAL }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordQualityRequirement
       implements Serializable
{
  /**
   * The BER type that will be used for the optional client-side validation info
   * element of an encoded password quality requirement.
   */
  private static final byte TYPE_CLIENT_SIDE_VALIDATION_INFO = (byte) 0xA1;



  /**
   * The BER type that will be used for the optional validation properties
   * element of an encoded client-side validation info element.
   */
  private static final byte TYPE_CLIENT_SIDE_VALIDATION_PROPERTIES =
       (byte) 0xA1;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2956655422853571644L;



  // A set of properties that may be used to indicate constraints that the
  // server will impose when validating the password in accordance with this
  // requirement.
  @NotNull private final Map<String,String> clientSideValidationProperties;

  // The name of the client-side validation type for this requirement, if any.
  @Nullable private final String clientSideValidationType;

  // A user-friendly description of the constraints that proposed passwords must
  // satisfy in order to be accepted by the server.
  @NotNull private final String description;



  /**
   * Creates a new password quality requirement object without any support for
   * client-side validation.
   *
   * @param  description  A user-friendly description of the constraints that a
   *                      proposed password must satisfy in order to meet this
   *                      requirement and be accepted by the server.  This must
   *                      not be {@code null}.
   */
  public PasswordQualityRequirement(@NotNull final String description)
  {
    this(description, null, null);
  }



  /**
   * Creates a new password quality requirement object with optional support for
   * client-side validation.
   *
   * @param  description                     A user-friendly description of the
   *                                         constraints that a proposed
   *                                         password must satisfy in order to
   *                                         meet this requirement and be
   *                                         accepted by the server.  This must
   *                                         not be {@code null}.
   * @param  clientSideValidationType        An optional string that identifies
   *                                         the type of validation associated
   *                                         with this requirement.
   *                                         Applications that support
   *                                         client-side validation and
   *                                         recognize this validation type can
   *                                         attempt to use their own logic in
   *                                         attempt to determine whether a
   *                                         proposed password may be rejected
   *                                         by the server because it does not
   *                                         satisfy this requirement.  This may
   *                                         be {@code null} if no client-side
   *                                         validation is available for this
   *                                         requirement.
   * @param  clientSideValidationProperties  An optional map of property names
   *                                         and values that may provide
   *                                         additional information that can be
   *                                         used for client-side validation.
   *                                         The properties that may be included
   *                                         depend on the validation type.
   *                                         This must be empty or {@code null}
   *                                         if the provided validation type is
   *                                         {@code null}.  It may also be empty
   *                                         or {@code null} if no additional
   *                                         properties are required for the
   *                                         associated type of client-side
   *                                         validation.
   */
  public PasswordQualityRequirement(@NotNull final String description,
              @Nullable final String clientSideValidationType,
              @Nullable final Map<String,String> clientSideValidationProperties)
  {
    Validator.ensureNotNull(description);

    if (clientSideValidationType == null)
    {
      Validator.ensureTrue((clientSideValidationProperties == null) ||
           clientSideValidationProperties.isEmpty());
    }

    this.description = description;
    this.clientSideValidationType = clientSideValidationType;

    if (clientSideValidationProperties == null)
    {
      this.clientSideValidationProperties = Collections.emptyMap();
    }
    else
    {
      this.clientSideValidationProperties = Collections.unmodifiableMap(
           new LinkedHashMap<>(clientSideValidationProperties));
    }
  }



  /**
   * Retrieves a user-friendly description of the constraints that a proposed
   * password must satisfy in order to meet this requirement and be accepted
   * by the server.
   *
   * @return  A user-friendly description for this password quality requirement.
   */
  @NotNull()
  public String getDescription()
  {
    return description;
  }



  /**
   * Retrieves a string that identifies the type of client-side validation that
   * may be performed by applications in order to identify potential problems
   * with a proposed password before sending it to the server.  Client-side
   * validation may not be available for all types of password quality
   * requirements.
   *
   * @return  The client side validation type for this password quality
   *          requirement, or {@code null} if client-side validation is not
   *          supported for this password quality requirement.
   */
  @Nullable()
  public String getClientSideValidationType()
  {
    return clientSideValidationType;
  }



  /**
   * Retrieves a set of properties that may be used in the course of performing
   * client-side validation for a proposed password.  The types of properties
   * that may be included depend on the client-side validation type.
   *
   * @return  A map of properties that may be used in the course of performing
   *          client-side validation, or an empty map if client-side validation
   *          is not available for this password quality requirement, or if no
   *          additional properties required for the associated type of
   *          client-side validation.
   */
  @NotNull()
  public Map<String,String> getClientSideValidationProperties()
  {
    return clientSideValidationProperties;
  }



  /**
   * Encodes this password quality requirement to an ASN.1 element that may be
   * included in LDAP protocol elements that may need to include it (e.g., a
   * get password quality requirements extended response or a password
   * validation details response control).
   *
   * @return  An ASN.1-encoded representation of this password quality
   *          requirement.
   */
  @NotNull()
  public ASN1Element encode()
  {
    final ArrayList<ASN1Element> requirementElements = new ArrayList<>(2);
    requirementElements.add(new ASN1OctetString(description));

    if (clientSideValidationType != null)
    {
      final ArrayList<ASN1Element> clientSideElements = new ArrayList<>(2);
      clientSideElements.add(new ASN1OctetString(clientSideValidationType));

      if (! clientSideValidationProperties.isEmpty())
      {
        final ArrayList<ASN1Element> propertyElements =
             new ArrayList<>(clientSideValidationProperties.size());
        for (final Map.Entry<String,String> e :
             clientSideValidationProperties.entrySet())
        {
          propertyElements.add(new ASN1Sequence(
               new ASN1OctetString(e.getKey()),
               new ASN1OctetString(e.getValue())));
        }
        clientSideElements.add(new ASN1Set(
             TYPE_CLIENT_SIDE_VALIDATION_PROPERTIES, propertyElements));
      }

      requirementElements.add(new ASN1Sequence(TYPE_CLIENT_SIDE_VALIDATION_INFO,
           clientSideElements));
    }

    return new ASN1Sequence(requirementElements);
  }



  /**
   * Decodes the provided ASN.1 element as a password quality requirement.
   *
   * @param  element  The ASN.1 element to decode as a password quality
   *                  requirement.  It must not be {@code null}.
   *
   * @return  The decoded password quality requirement.
   *
   * @throws  LDAPException  If a problem was encountered while attempting to
   *                         decode the provided ASN.1 element as a password
   *                         quality requirement.
   */
  @NotNull()
  public static PasswordQualityRequirement decode(
              @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] requirementElements =
           ASN1Sequence.decodeAsSequence(element).elements();

      final String description = ASN1OctetString.decodeAsOctetString(
           requirementElements[0]).stringValue();

      String clientSideValidationType = null;
      Map<String,String> clientSideValidationProperties = null;
      for (int i=1; i < requirementElements.length; i++)
      {
        final ASN1Element requirementElement = requirementElements[i];
        switch (requirementElement.getType())
        {
          case TYPE_CLIENT_SIDE_VALIDATION_INFO:
            final ASN1Element[] csvInfoElements =
                 ASN1Sequence.decodeAsSequence(requirementElement).elements();
            clientSideValidationType = ASN1OctetString.decodeAsOctetString(
                 csvInfoElements[0]).stringValue();

            for (int j=1; j < csvInfoElements.length; j++)
            {
              final ASN1Element csvInfoElement = csvInfoElements[j];
              switch (csvInfoElement.getType())
              {
                case TYPE_CLIENT_SIDE_VALIDATION_PROPERTIES:
                  final ASN1Element[] csvPropElements =
                       ASN1Sequence.decodeAsSequence(csvInfoElement).elements();
                  clientSideValidationProperties = new LinkedHashMap<>(
                       StaticUtils.computeMapCapacity(csvPropElements.length));
                  for (final ASN1Element csvPropElement : csvPropElements)
                  {
                    final ASN1Element[] propElements =
                         ASN1Sequence.decodeAsSequence(
                              csvPropElement).elements();
                    final String name = ASN1OctetString.decodeAsOctetString(
                         propElements[0]).stringValue();
                    final String value = ASN1OctetString.decodeAsOctetString(
                         propElements[1]).stringValue();
                    clientSideValidationProperties.put(name, value);
                  }
                  break;

                default:
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_PW_QUALITY_REQ_INVALID_CSV_ELEMENT_TYPE.get(
                            StaticUtils.toHex(csvInfoElement.getType())));
              }
            }

            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_PW_QUALITY_REQ_INVALID_REQ_ELEMENT_TYPE.get(
                      StaticUtils.toHex(requirementElement.getType())));
        }
      }

      return new PasswordQualityRequirement(description,
           clientSideValidationType, clientSideValidationProperties);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_PW_QUALITY_REQ_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves a string representation of this password quality requirement.
   *
   * @return  A string representation of this password quality requirement.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this password quality requirement to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PasswordQualityRequirement(description='");
    buffer.append(description);
    buffer.append('\'');

    if (clientSideValidationType != null)
    {
      buffer.append(", clientSideValidationType='");
      buffer.append(clientSideValidationType);
      buffer.append('\'');

      if (! clientSideValidationProperties.isEmpty())
      {
        buffer.append(", clientSideValidationProperties={");

        final Iterator<Map.Entry<String,String>> iterator =
             clientSideValidationProperties.entrySet().iterator();
        while (iterator.hasNext())
        {
          final Map.Entry<String,String> e = iterator.next();

          buffer.append('\'');
          buffer.append(e.getKey());
          buffer.append("'='");
          buffer.append(e.getValue());
          buffer.append('\'');

          if (iterator.hasNext())
          {
            buffer.append(',');
          }
        }

        buffer.append('}');
      }
    }

    buffer.append(')');
  }
}
