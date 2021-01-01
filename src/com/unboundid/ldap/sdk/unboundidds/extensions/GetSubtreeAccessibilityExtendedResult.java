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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended result that holds
 * information about the response returned from a
 * {@link GetSubtreeAccessibilityExtendedRequest}.
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
 * It has an OID of 1.3.6.1.4.1.30221.1.6.21, and successful responses will have
 * a value with the following encoding:
 * <BR><BR>
 * <PRE>
 *   GetSubtreeAccessibilityResultValue ::= SEQUENCE OF SEQUENCE {
 *        subtreeBaseDN            [0] LDAPDN,
 *        subtreeAccessibility     [1] ENUMERATED {
 *             accessible                 (0),
 *             read-only-bind-allowed     (1),
 *             read-only-bind-denied      (2),
 *             hidden                     (3),
 *             ... },
 *        bypassUserDN             [2] LDAPDN OPTIONAL,
 *        effectiveTime            [3] OCTET STRING,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetSubtreeAccessibilityExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.1.6.21) for the get subtree accessibility
   * extended result.
   */
  @NotNull public static final String GET_SUBTREE_ACCESSIBILITY_RESULT_OID =
       "1.3.6.1.4.1.30221.1.6.21";



  /**
   * The BER type for the element that holds the base DN for a subtree
   * accessibility restriction.
   */
  private static final byte TYPE_BASE_DN = (byte) 0x80;



  /**
   * The BER type for the element that holds the accessibility state for a
   * subtree accessibility restriction.
   */
  private static final byte TYPE_STATE = (byte) 0x81;



  /**
   * The BER type for the element that holds the bypass user DN for a subtree
   * accessibility restriction.
   */
  private static final byte TYPE_BYPASS_USER = (byte) 0x82;



  /**
   * The BER type for the element that holds the effective time for a subtree
   * accessibility restriction.
   */
  private static final byte TYPE_EFFECTIVE_TIME = (byte) 0x83;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3163306122775326749L;



  // A list of the subtree accessibility restrictions defined in the server.
  @Nullable private final List<SubtreeAccessibilityRestriction>
       accessibilityRestrictions;



  /**
   * Creates a new get subtree accessibility extended result from the provided
   * generic extended result.
   *
   * @param  extendedResult  The generic extended result to be decoded.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided extended result as a get connection ID
   *                         result.
   */
  public GetSubtreeAccessibilityExtendedResult(
              @NotNull final ExtendedResult extendedResult)
         throws LDAPException
  {
    super(extendedResult);

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      accessibilityRestrictions = null;
      return;
    }

    try
    {
      final ASN1Element[] restrictionElements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      final ArrayList<SubtreeAccessibilityRestriction> restrictionList =
           new ArrayList<>(restrictionElements.length);

      for (final ASN1Element e : restrictionElements)
      {
        String baseDN = null;
        SubtreeAccessibilityState state = null;
        String bypassDN = null;
        Date effectiveTime = null;

        for (final ASN1Element re : ASN1Sequence.decodeAsSequence(e).elements())
        {
          switch (re.getType())
          {
            case TYPE_BASE_DN:
              baseDN = ASN1OctetString.decodeAsOctetString(re).stringValue();
              break;
            case TYPE_STATE:
              state = SubtreeAccessibilityState.valueOf(
                   ASN1Enumerated.decodeAsEnumerated(re).intValue());
              if (state == null)
              {
                throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_GET_SUBTREE_ACCESSIBILITY_RESULT_UNEXPECTED_STATE.get(
                          ASN1Enumerated.decodeAsEnumerated(re).intValue()));
              }
              break;
            case TYPE_BYPASS_USER:
              bypassDN = ASN1OctetString.decodeAsOctetString(re).stringValue();
              break;
            case TYPE_EFFECTIVE_TIME:
              effectiveTime = StaticUtils.decodeGeneralizedTime(
                   ASN1OctetString.decodeAsOctetString(re).stringValue());
              break;
            default:
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_GET_SUBTREE_ACCESSIBILITY_RESULT_UNEXPECTED_TYPE.get(
                        StaticUtils.toHex(re.getType())));
          }
        }

        if (baseDN == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_GET_SUBTREE_ACCESSIBILITY_RESULT_MISSING_BASE.get());
        }

        if (state == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_GET_SUBTREE_ACCESSIBILITY_RESULT_MISSING_STATE.get());
        }

        if (effectiveTime == null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_GET_SUBTREE_ACCESSIBILITY_RESULT_MISSING_TIME.get());
        }

        restrictionList.add(new SubtreeAccessibilityRestriction(baseDN, state,
             bypassDN, effectiveTime));
      }

      accessibilityRestrictions = Collections.unmodifiableList(restrictionList);
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
           ERR_GET_SUBTREE_ACCESSIBILITY_RESULT_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new get subtree accessibility extended result with the provided
   * information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  restrictions       The set of subtree accessibility restrictions
   *                            to include in the response.  It may be
   *                            {@code null} if this represents an error
   *                            response, or it may be empty if there are no
   *                            subtree accessibility restrictions defined in
   *                            the server.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public GetSubtreeAccessibilityExtendedResult(final int messageID,
       @NotNull final ResultCode resultCode,
       @Nullable final String diagnosticMessage,
       @Nullable final String matchedDN,
       @Nullable final String[] referralURLs,
       @Nullable final Collection<SubtreeAccessibilityRestriction> restrictions,
       @Nullable final Control... responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
          null, encodeValue(restrictions), responseControls);

    if (restrictions == null)
    {
      accessibilityRestrictions = null;
    }
    else
    {
      accessibilityRestrictions = Collections.unmodifiableList(
           new ArrayList<>(restrictions));
    }
  }



  /**
   * Encodes the value for this extended result using the provided information.
   *
   * @param  restrictions  The set of subtree accessibility restrictions to
   *                       include in the response.  It may be {@code null} if
   *                       this represents an error response, or it may be empty
   *                       if there are no subtree accessibility restrictions
   *                       defined in the server.
   *
   * @return  An ASN.1 octet string containing the properly-encoded value, or
   *          {@code null} if there should be no value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
       @Nullable final Collection<SubtreeAccessibilityRestriction> restrictions)
  {
    if (restrictions == null)
    {
      return null;
    }

    final ArrayList<ASN1Element> elements =
         new ArrayList<>(restrictions.size());
    for (final SubtreeAccessibilityRestriction r : restrictions)
    {
      final ArrayList<ASN1Element> restrictionElements = new ArrayList<>(4);
      restrictionElements.add(new ASN1OctetString(TYPE_BASE_DN,
           r.getSubtreeBaseDN()));
      restrictionElements.add(new ASN1Enumerated(TYPE_STATE,
           r.getAccessibilityState().intValue()));

      if (r.getBypassUserDN() != null)
      {
        restrictionElements.add(new ASN1OctetString(TYPE_BYPASS_USER,
             r.getBypassUserDN()));
      }

      restrictionElements.add(new ASN1OctetString(TYPE_EFFECTIVE_TIME,
           StaticUtils.encodeGeneralizedTime(r.getEffectiveTime())));

      elements.add(new ASN1Sequence(restrictionElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves a list of the subtree accessibility restrictions defined in the
   * server.
   *
   * @return  A list of the subtree accessibility restrictions defined in the
   *          server, an empty list if there are no restrictions defined, or
   *          {@code null} if no restriction data was included in the response
   *          from the server (e.g., because it was an error response).
   */
  @Nullable()
  public List<SubtreeAccessibilityRestriction> getAccessibilityRestrictions()
  {
    return accessibilityRestrictions;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_GET_SUBTREE_ACCESSIBILITY.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetSubtreeAccessibilityExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    final String diagnosticMessage = getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    final String matchedDN = getMatchedDN();
    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    final String[] referralURLs = getReferralURLs();
    if ((referralURLs != null) && (referralURLs.length > 0))
    {
      buffer.append(", referralURLs={ '");
      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append("', '");
        }
        buffer.append(referralURLs[i]);
      }

      buffer.append("' }");
    }

    if (accessibilityRestrictions != null)
    {
      buffer.append(", accessibilityRestrictions={");

      final Iterator<SubtreeAccessibilityRestriction> iterator =
           accessibilityRestrictions.iterator();
      while (iterator.hasNext())
      {
        iterator.next().toString(buffer);
        if (iterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }

    final Control[] controls = getResponseControls();
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
