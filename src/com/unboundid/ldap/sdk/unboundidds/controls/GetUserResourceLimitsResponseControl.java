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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Long;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a response control that may be included in the response
 * to a successful bind operation in order to provide information about custom
 * resource limits for the user, including size limit, time limit, idle time
 * limit, lookthrough limit, equivalent authorization user DN, and client
 * connection policy name.
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
 * The criticality for this control should be {@code false}.  It must have a
 * value with the following encoding:
 * <PRE>
 *   USER_RESOURCE_LIMITS_VALUE ::= SEQUENCE {
 *     sizeLimit                      [0] INTEGER OPTIONAL,
 *     timeLimitSeconds               [1] INTEGER OPTIONAL,
 *     idleTimeLimitSeconds           [2] INTEGER OPTIONAL,
 *     lookthroughLimit               [3] INTEGER OPTIONAL,
 *     equivalentAuthzUserDN          [4] LDAPDN OPTIONAL,
 *     clientConnectionPolicyName     [5] OCTET STRING OPTIONAL,
 *     groupDNs                       [6] SET OF OCTET STRING OPTIONAL,
 *     privilegeNames                 [7] SET OF OCTET STRING OPTIONAL,
 *     otherAttributes                [8] PartialAttributeList OPTIONAL,
 *     ... }
 * </PRE>
 *
 * @see GetUserResourceLimitsRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetUserResourceLimitsResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.26) for the get user resource limits
   * response control.
   */
  @NotNull public static final String GET_USER_RESOURCE_LIMITS_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.26";



  /**
   * The BER type for the value element used to specify the size limit.
   */
  private static final byte TYPE_SIZE_LIMIT = (byte) 0x80;



  /**
   * The BER type for the value element used to specify the time limit.
   */
  private static final byte TYPE_TIME_LIMIT = (byte) 0x81;



  /**
   * The BER type for the value element used to specify the idle time limit.
   */
  private static final byte TYPE_IDLE_TIME_LIMIT = (byte) 0x82;



  /**
   * The BER type for the value element used to specify the lookthrough limit.
   */
  private static final byte TYPE_LOOKTHROUGH_LIMIT = (byte) 0x83;



  /**
   * The BER type for the value element used to specify the equivalent
   * authorization user DN.
   */
  private static final byte TYPE_EQUIVALENT_AUTHZ_USER_DN = (byte) 0x84;



  /**
   * The BER type for the value element used to specify the client connection
   * policy name.
   */
  private static final byte TYPE_CLIENT_CONNECTION_POLICY_NAME = (byte) 0x85;



  /**
   * The BER type for the value element used to specify the DNs of groups in
   * which the user is a member.
   */
  private static final byte TYPE_GROUP_DNS = (byte) 0xA6;



  /**
   * The BER type for the value element used to specify the set of user
   * privilege names.
   */
  private static final byte TYPE_PRIVILEGE_NAMES = (byte) 0xA7;



  /**
   * The BER type for the value element used to specify additional attributes
   * that may be included in the future.
   */
  private static final byte TYPE_OTHER_ATTRIBUTES = (byte) 0xA8;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5261978490319320250L;



  // The set of other select attributes from the user entry.
  @NotNull private final List<Attribute> otherAttributes;

  // The set of group DNs for the user.
  @Nullable private final List<String> groupDNs;

  // The set of privilege names for the user.
  @Nullable private final List<String> privilegeNames;

  // The custom idle time limit for the user.
  @Nullable private final Long idleTimeLimitSeconds;

  // The custom lookthrough limit for the user.
  @Nullable private final Long lookthroughLimit;

  // The custom size limit for the user.
  @Nullable private final Long sizeLimit;

  // The custom time limit for the user, in seconds.
  @Nullable private final Long timeLimitSeconds;

  // The name of the client connection policy selected for the user.
  @Nullable private final String clientConnectionPolicyName;

  // The DN of a user with equivalent authorization rights for use in servers
  // in an entry-balancing environment in which the user's entry does not exist.
  @Nullable private final String equivalentAuthzUserDN;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  GetUserResourceLimitsResponseControl()
  {
    otherAttributes            = null;
    groupDNs                   = null;
    privilegeNames             = null;
    idleTimeLimitSeconds       = null;
    lookthroughLimit           = null;
    sizeLimit                  = null;
    timeLimitSeconds           = null;
    clientConnectionPolicyName = null;
    equivalentAuthzUserDN      = null;
  }



  /**
   * Creates a new get user resource limits response control with the provided
   * information.
   *
   * @param  sizeLimit                   The custom size limit for the user.
   *                                     It may be less than or equal to zero
   *                                     if no size limit should be enforced for
   *                                     the user.  It may be {@code null} if
   *                                     there is no custom size limit or it is
   *                                     not to be included in the control.
   * @param  timeLimitSeconds            The custom time limit for the user, in
   *                                     seconds.  It may be less than or equal
   *                                     to zero if no time limit should be
   *                                     enforced for the user.  It may be
   *                                     {@code null} if there is no custom time
   *                                     limit or it is not to be included in
   *                                     the control.
   * @param  idleTimeLimitSeconds        The custom idle time limit for the
   *                                     user, in seconds.  It may be less than
   *                                     or equal to zero if no idle time limit
   *                                     should be enforced for the user.  It
   *                                     may be {@code null} if there is no
   *                                     custom idle time limit or it is not to
   *                                     be included in the control.
   * @param  lookthroughLimit            The custom lookthrough limit for the
   *                                     user.  It may be less than or equal to
   *                                     zero if no lookthrough limit should
   *                                     be enforced for the user.  It may be
   *                                     {@code null} if there is no custom
   *                                     lookthrough limit for the user or it is
   *                                     not to be included in the control.
   * @param  equivalentAuthzUserDN       The DN of a user with equivalent
   *                                     authorization rights for use in servers
   *                                     in an entry-balancing environment in
   *                                     which the user's entry does not exist.
   *                                     It may be an empty string if the
   *                                     equivalent authorization should be
   *                                     anonymous, or {@code null} if there is
   *                                     no custom equivalent authorization user
   *                                     DN or it is not to be included in the
   *                                     control.
   * @param  clientConnectionPolicyName  The name of the client connection
   *                                     policy that has been assigned to the
   *                                     user, or {@code null} if the client
   *                                     connection policy name is not to be
   *                                     included in the control.
   */
  public GetUserResourceLimitsResponseControl(@Nullable final Long sizeLimit,
              @Nullable final Long timeLimitSeconds,
              @Nullable final Long idleTimeLimitSeconds,
              @Nullable final Long lookthroughLimit,
              @Nullable final String equivalentAuthzUserDN,
              @Nullable final String clientConnectionPolicyName)
  {
    this(sizeLimit, timeLimitSeconds, idleTimeLimitSeconds, lookthroughLimit,
         equivalentAuthzUserDN, clientConnectionPolicyName, null, null, null);
  }



  /**
   * Creates a new get user resource limits response control with the provided
   * information.
   *
   * @param  sizeLimit                   The custom size limit for the user.
   *                                     It may be less than or equal to zero
   *                                     if no size limit should be enforced for
   *                                     the user.  It may be {@code null} if
   *                                     there is no custom size limit or it is
   *                                     not to be included in the control.
   * @param  timeLimitSeconds            The custom time limit for the user, in
   *                                     seconds.  It may be less than or equal
   *                                     to zero if no time limit should be
   *                                     enforced for the user.  It may be
   *                                     {@code null} if there is no custom time
   *                                     limit or it is not to be included in
   *                                     the control.
   * @param  idleTimeLimitSeconds        The custom idle time limit for the
   *                                     user, in seconds.  It may be less than
   *                                     or equal to zero if no idle time limit
   *                                     should be enforced for the user.  It
   *                                     may be {@code null} if there is no
   *                                     custom idle time limit or it is not to
   *                                     be included in the control.
   * @param  lookthroughLimit            The custom lookthrough limit for the
   *                                     user.  It may be less than or equal to
   *                                     zero if no lookthrough limit should
   *                                     be enforced for the user.  It may be
   *                                     {@code null} if there is no custom
   *                                     lookthrough limit for the user or it is
   *                                     not to be included in the control.
   * @param  equivalentAuthzUserDN       The DN of a user with equivalent
   *                                     authorization rights for use in servers
   *                                     in an entry-balancing environment in
   *                                     which the user's entry does not exist.
   *                                     It may be an empty string if the
   *                                     equivalent authorization should be
   *                                     anonymous, or {@code null} if there is
   *                                     no custom equivalent authorization user
   *                                     DN or it is not to be included in the
   *                                     control.
   * @param  clientConnectionPolicyName  The name of the client connection
   *                                     policy that has been assigned to the
   *                                     user, or {@code null} if the client
   *                                     connection policy name is not to be
   *                                     included in the control.
   * @param  groupDNs                    The DNs of the groups in which the user
   *                                     is a member.  It may be {@code null} if
   *                                     group membership is not known, or
   *                                     empty if the user isn't a member of any
   *                                     groups.
   * @param  privilegeNames              The names of the privileges assigned to
   *                                     the user.  It may be {@code null} if
   *                                     the privilege names are not known, or
   *                                     empty if the  user doesn't have any
   *                                     privileges.
   * @param  otherAttributes             A set of additional attributes from the
   *                                     user's entry.  It may be {@code null}
   *                                     or empty if no additional attributes
   *                                     are needed.
   */
  public GetUserResourceLimitsResponseControl(@Nullable final Long sizeLimit,
              @Nullable final Long timeLimitSeconds,
              @Nullable final Long idleTimeLimitSeconds,
              @Nullable final Long lookthroughLimit,
              @Nullable final String equivalentAuthzUserDN,
              @Nullable final String clientConnectionPolicyName,
              @Nullable final List<String> groupDNs,
              @Nullable final List<String> privilegeNames,
              @Nullable final List<Attribute> otherAttributes)
  {
    super(GET_USER_RESOURCE_LIMITS_RESPONSE_OID, false,
         encodeValue(sizeLimit, timeLimitSeconds, idleTimeLimitSeconds,
              lookthroughLimit, equivalentAuthzUserDN,
              clientConnectionPolicyName, groupDNs, privilegeNames,
              otherAttributes));

    if ((sizeLimit == null) || (sizeLimit > 0L))
    {
      this.sizeLimit = sizeLimit;
    }
    else
    {
      this.sizeLimit = -1L;
    }

    if ((timeLimitSeconds == null) || (timeLimitSeconds > 0L))
    {
      this.timeLimitSeconds = timeLimitSeconds;
    }
    else
    {
      this.timeLimitSeconds = -1L;
    }

    if ((idleTimeLimitSeconds == null) || (idleTimeLimitSeconds > 0L))
    {
      this.idleTimeLimitSeconds = idleTimeLimitSeconds;
    }
    else
    {
      this.idleTimeLimitSeconds = -1L;
    }

    if ((lookthroughLimit == null) || (lookthroughLimit > 0L))
    {
      this.lookthroughLimit = lookthroughLimit;
    }
    else
    {
      this.lookthroughLimit = -1L;
    }

    this.equivalentAuthzUserDN      = equivalentAuthzUserDN;
    this.clientConnectionPolicyName = clientConnectionPolicyName;

    if (groupDNs == null)
    {
      this.groupDNs = null;
    }
    else
    {
      this.groupDNs =
           Collections.unmodifiableList(new ArrayList<>(groupDNs));
    }

    if (privilegeNames == null)
    {
      this.privilegeNames = null;
    }
    else
    {
      this.privilegeNames =
           Collections.unmodifiableList(new ArrayList<>(privilegeNames));
    }

    if (otherAttributes == null)
    {
      this.otherAttributes = Collections.emptyList();
    }
    else
    {
      this.otherAttributes =
           Collections.unmodifiableList(new ArrayList<>(otherAttributes));
    }
  }



  /**
   * Encodes the provided information into an octet string suitable for use as
   * the value of a get user resource limits response control.
   *
   * @param  sizeLimit                   The custom size limit for the user.
   *                                     It may be less than or equal to zero
   *                                     if no size limit should be enforced for
   *                                     the user.  It may be {@code null} if
   *                                     there is no custom size limit or it is
   *                                     not to be included in the control.
   * @param  timeLimitSeconds            The custom time limit for the user, in
   *                                     seconds.  It may be less than or equal
   *                                     to zero if no time limit should be
   *                                     enforced for the user.  It may be
   *                                     {@code null} if there is no custom time
   *                                     limit or it is not to be included in
   *                                     the control.
   * @param  idleTimeLimitSeconds        The custom idle time limit for the
   *                                     user, in seconds.  It may be less than
   *                                     or equal to zero if no idle time limit
   *                                     should be enforced for the user.  It
   *                                     may be {@code null} if there is no
   *                                     custom idle time limit or it is not to
   *                                     be included in the control.
   * @param  lookthroughLimit            The custom lookthrough limit for the
   *                                     user.  It may be less than or equal to
   *                                     zero if no lookthrough limit should
   *                                     be enforced for the user.  It may be
   *                                     {@code null} if there is no custom
   *                                     lookthrough limit for the user or it is
   *                                     not to be included in the control.
   * @param  equivalentAuthzUserDN       The DN of a user with equivalent
   *                                     authorization rights for use in servers
   *                                     in an entry-balancing environment in
   *                                     which the user's entry does not exist.
   * @param  clientConnectionPolicyName  The name of the client connection
   *                                     policy that has been assigned to the
   *                                     user, or {@code null} if the client
   *                                     connection policy name is not to be
   *                                     included in the control.
   * @param  groupDNs                    The DNs of the groups in which the user
   *                                     is a member.  It may be {@code null} if
   *                                     group membership is not known, or
   *                                     empty if the user isn't a member of any
   *                                     groups.
   * @param  privilegeNames              The names of the privileges assigned to
   *                                     the user.  It may be {@code null} if
   *                                     the privilege names are not known, or
   *                                     empty if the  user doesn't have any
   *                                     privileges.
   * @param  otherAttributes             A set of additional attributes from the
   *                                     user's entry.  It may be {@code null}
   *                                     or empty if no additional attributes
   *                                     are needed.
   *
   * @return  The octet string which may be used as the value of a get user
   *          resource limits response control
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@Nullable final Long sizeLimit,
              @Nullable final Long timeLimitSeconds,
              @Nullable final Long idleTimeLimitSeconds,
              @Nullable final Long lookthroughLimit,
              @Nullable final String equivalentAuthzUserDN,
              @Nullable final String clientConnectionPolicyName,
              @Nullable final List<String> groupDNs,
              @Nullable final List<String> privilegeNames,
              @Nullable final List<Attribute> otherAttributes)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(10);

    if (sizeLimit != null)
    {
      if (sizeLimit > 0L)
      {
        elements.add(new ASN1Long(TYPE_SIZE_LIMIT, sizeLimit));
      }
      else
      {
        elements.add(new ASN1Long(TYPE_SIZE_LIMIT, -1L));
      }
    }

    if (timeLimitSeconds != null)
    {
      if (timeLimitSeconds > 0L)
      {
        elements.add(new ASN1Long(TYPE_TIME_LIMIT, timeLimitSeconds));
      }
      else
      {
        elements.add(new ASN1Long(TYPE_TIME_LIMIT, -1L));
      }
    }

    if (idleTimeLimitSeconds != null)
    {
      if (idleTimeLimitSeconds > 0L)
      {
        elements.add(new ASN1Long(TYPE_IDLE_TIME_LIMIT, idleTimeLimitSeconds));
      }
      else
      {
        elements.add(new ASN1Long(TYPE_IDLE_TIME_LIMIT, -1L));
      }
    }

    if (lookthroughLimit != null)
    {
      if (lookthroughLimit > 0L)
      {
        elements.add(new ASN1Long(TYPE_LOOKTHROUGH_LIMIT, lookthroughLimit));
      }
      else
      {
        elements.add(new ASN1Long(TYPE_LOOKTHROUGH_LIMIT, -1L));
      }
    }

    if (equivalentAuthzUserDN != null)
    {
      elements.add(new ASN1OctetString(TYPE_EQUIVALENT_AUTHZ_USER_DN,
           equivalentAuthzUserDN));
    }

    if (clientConnectionPolicyName != null)
    {
      elements.add(new ASN1OctetString(TYPE_CLIENT_CONNECTION_POLICY_NAME,
           clientConnectionPolicyName));
    }

    if (groupDNs != null)
    {
      final ArrayList<ASN1Element> dnElements =
           new ArrayList<>(groupDNs.size());
      for (final String s : groupDNs)
      {
        dnElements.add(new ASN1OctetString(s));
      }

      elements.add(new ASN1Set(TYPE_GROUP_DNS, dnElements));
    }

    if (privilegeNames != null)
    {
      final ArrayList<ASN1Element> privElements =
           new ArrayList<>(privilegeNames.size());
      for (final String s : privilegeNames)
      {
        privElements.add(new ASN1OctetString(s));
      }

      elements.add(new ASN1Set(TYPE_PRIVILEGE_NAMES, privElements));
    }

    if ((otherAttributes != null) && (! otherAttributes.isEmpty()))
    {
      final ArrayList<ASN1Element> attrElements =
           new ArrayList<>(otherAttributes.size());
      for (final Attribute a : otherAttributes)
      {
        attrElements.add(a.encode());
      }

      elements.add(new ASN1Sequence(TYPE_OTHER_ATTRIBUTES, attrElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Creates a new get user resource limits response control decoded from the
   * given generic control contents.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  value       The value for the control.  It may be {@code null} if
   *                     the control to decode does not have a value.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         generic control as a get user resource limits
   *                         response control.
   */
  public GetUserResourceLimitsResponseControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_USER_RESOURCE_LIMITS_RESPONSE_MISSING_VALUE.get());
    }


    List<Attribute> oa   = Collections.emptyList();
    List<String>    gd   = null;
    List<String>    pn   = null;
    Long            sL   = null;
    Long            tL   = null;
    Long            iTL  = null;
    Long            lL   = null;
    String          eAUD = null;
    String          cCPN = null;

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      for (final ASN1Element e : elements)
      {
        switch (e.getType())
        {
          case TYPE_SIZE_LIMIT:
            sL = ASN1Long.decodeAsLong(e).longValue();
            break;
          case TYPE_TIME_LIMIT:
            tL = ASN1Long.decodeAsLong(e).longValue();
            break;
          case TYPE_IDLE_TIME_LIMIT:
            iTL = ASN1Long.decodeAsLong(e).longValue();
            break;
          case TYPE_LOOKTHROUGH_LIMIT:
            lL = ASN1Long.decodeAsLong(e).longValue();
            break;
          case TYPE_EQUIVALENT_AUTHZ_USER_DN:
            eAUD = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_CLIENT_CONNECTION_POLICY_NAME:
            cCPN = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_GROUP_DNS:
            final ASN1Element[] groupElements =
                 ASN1Set.decodeAsSet(e).elements();
            gd = new ArrayList<>(groupElements.length);
            for (final ASN1Element pe : groupElements)
            {
              gd.add(ASN1OctetString.decodeAsOctetString(pe).stringValue());
            }
            gd = Collections.unmodifiableList(gd);
            break;
          case TYPE_PRIVILEGE_NAMES:
            final ASN1Element[] privElements =
                 ASN1Set.decodeAsSet(e).elements();
            pn = new ArrayList<>(privElements.length);
            for (final ASN1Element pe : privElements)
            {
              pn.add(ASN1OctetString.decodeAsOctetString(pe).stringValue());
            }
            pn = Collections.unmodifiableList(pn);
            break;
          case TYPE_OTHER_ATTRIBUTES:
            final ASN1Element[] attrElemnets =
                 ASN1Sequence.decodeAsSequence(e).elements();
            oa = new ArrayList<>(attrElemnets.length);
            for (final ASN1Element ae : attrElemnets)
            {
              oa.add(Attribute.decode(ASN1Sequence.decodeAsSequence(ae)));
            }
            oa = Collections.unmodifiableList(oa);
            break;
          default:
            // No action will be taken.  It may be the case that a future
            // version of the control could return additional information.
            break;
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_USER_RESOURCE_LIMITS_RESPONSE_CANNOT_DECODE_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    otherAttributes            = oa;
    groupDNs                   = gd;
    privilegeNames             = pn;
    sizeLimit                  = sL;
    timeLimitSeconds           = tL;
    idleTimeLimitSeconds       = iTL;
    lookthroughLimit           = lL;
    equivalentAuthzUserDN      = eAUD;
    clientConnectionPolicyName = cCPN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetUserResourceLimitsResponseControl decodeControl(
              @NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new GetUserResourceLimitsResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts a get user resource limits response control from the provided
   * result.
   *
   * @param  result  The bind result from which to retrieve the get user
   *                 resource limits response control.
   *
   * @return  The get user resource limits response control contained in the
   *          provided result, or {@code null} if the result did not contain a
   *          get user resource limits response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the get user resource limits response
   *                         control contained in the provided result.
   */
  @Nullable()
  public static GetUserResourceLimitsResponseControl get(
                     @NotNull final BindResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(GET_USER_RESOURCE_LIMITS_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GetUserResourceLimitsResponseControl)
    {
      return (GetUserResourceLimitsResponseControl) c;
    }
    else
    {
      return new GetUserResourceLimitsResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  /**
   * Retrieves the custom size limit for the user, if available.
   *
   * @return  The custom size limit for the user, -1 if no size limit should be
   *          enforced for the user, or {@code null} if no custom size limit
   *          was included in the control.
   */
  @Nullable()
  public Long getSizeLimit()
  {
    return sizeLimit;
  }



  /**
   * Retrieves the custom time limit for the user in seconds, if available.
   *
   * @return  The custom time limit for the user in seconds, -1 if no time limit
   *          should be enforced for the user, or {@code null} if no custom time
   *          limit was included in the control.
   */
  @Nullable()
  public Long getTimeLimitSeconds()
  {
    return timeLimitSeconds;
  }



  /**
   * Retrieves the custom idle time limit for the user in seconds, if available.
   *
   * @return  The custom idle time limit for the user in seconds, -1 if no idle
   *          time limit should be enforced for the user, or {@code null} if no
   *          custom idle time limit was included in the control.
   */
  @Nullable()
  public Long getIdleTimeLimitSeconds()
  {
    return idleTimeLimitSeconds;
  }



  /**
   * Retrieves the custom lookthrough limit for the user, if available.
   *
   * @return  The custom lookthrough limit for the user, -1 if no lookthrough
   *          limit should be enforced for the user, or {@code null} if no
   *          custom lookthrough limit was included in the control.
   */
  @Nullable()
  public Long getLookthroughLimit()
  {
    return lookthroughLimit;
  }



  /**
   * Retrieves the equivalent authorization user DN, for use in servers in an
   * entry-balancing environment in which the user's entry does not exist.
   *
   * @return  The equivalent authorization user DN for the user, an empty string
   *          if the equivalent authorization is anonymous, or {@code null} if
   *          no equivalent authorization user DN was included in the control.
   */
  @Nullable()
  public String getEquivalentAuthzUserDN()
  {
    return equivalentAuthzUserDN;
  }



  /**
   * Retrieves the name of the client connection policy that has been assigned
   * to the user, if available.
   *
   * @return  The name of the client connection policy that has been assigned to
   *          the user, or {@code null} if the client connection policy name was
   *          not included in the control.
   */
  @Nullable()
  public String getClientConnectionPolicyName()
  {
    return clientConnectionPolicyName;
  }



  /**
   * Retrieves the DNs of any groups in which the user is a member.
   *
   * @return  The DNs of any groups in which the user is a member, an empty list
   *          if the user is not a member of any groups, or {@code null} if the
   *           set of group DNs is not known.
   */
  @Nullable()
  public List<String> getGroupDNs()
  {
    return groupDNs;
  }



  /**
   * Retrieves the names of any privileges assigned to the user.
   *
   * @return  The names of any privileges assigned to the user, an empty list if
   *          the user is known to have no privileges, or {@code null} if the
   *          set of user privileges is not known.
   */
  @Nullable()
  public List<String> getPrivilegeNames()
  {
    return privilegeNames;
  }



  /**
   * Retrieves a list containing additional attributes from the user's entry.
   *
   * @return  A list containing additional attributes from the user's entry, or
   *          an empty list if no additional attributes were provided.
   */
  @NotNull
  public List<Attribute> getOtherAttributes()
  {
    return otherAttributes;
  }



  /**
   * Retrieves the "other" attribute with the specified name.
   *
   * @param  name  The name of the "other" attribute to retrieve.  It must not
   *               be {@code null}.
   *
   * @return  The "other" attribute with the specified name, or {@code null} if
   *          there is no such "other" attribute.
   */
  @Nullable()
  public Attribute getOtherAttribute(@NotNull final String name)
  {
    for (final Attribute a : otherAttributes)
    {
      if (a.getName().equalsIgnoreCase(name))
      {
        return a;
      }
    }

    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GET_USER_RESOURCE_LIMITS_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetUserResourceLimitsResponseControl(");

    boolean added = false;
    if (sizeLimit != null)
    {
      buffer.append("sizeLimit=");
      buffer.append(sizeLimit);
      added = true;
    }

    if (timeLimitSeconds != null)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("timeLimitSeconds=");
      buffer.append(timeLimitSeconds);
      added = true;
    }

    if (idleTimeLimitSeconds != null)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("idleTimeLimitSeconds=");
      buffer.append(idleTimeLimitSeconds);
      added = true;
    }

    if (lookthroughLimit != null)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("lookthroughLimit=");
      buffer.append(lookthroughLimit);
      added = true;
    }

    if (equivalentAuthzUserDN != null)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("equivalentAuthzUserDN=\"");
      buffer.append(equivalentAuthzUserDN);
      buffer.append('"');
      added = true;
    }

    if (clientConnectionPolicyName != null)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("clientConnectionPolicyName=\"");
      buffer.append(clientConnectionPolicyName);
      buffer.append('"');
      added = true;
    }

    if (groupDNs != null)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("groupDNs={");

      final Iterator<String> dnIterator = groupDNs.iterator();
      while (dnIterator.hasNext())
      {
        buffer.append('"');
        buffer.append(dnIterator.next());
        buffer.append('"');

        if (dnIterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
      added = true;
    }

    if (privilegeNames != null)
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("privilegeNames={");

      final Iterator<String> privilegeIterator = privilegeNames.iterator();
      while (privilegeIterator.hasNext())
      {
        buffer.append('"');
        buffer.append(privilegeIterator.next());
        buffer.append('"');

        if (privilegeIterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
      added = true;
    }

    if (! otherAttributes.isEmpty())
    {
      if (added)
      {
        buffer.append(", ");
      }

      buffer.append("otherAttributes={");

      final Iterator<Attribute> attrIterator = otherAttributes.iterator();
      while (attrIterator.hasNext())
      {
        attrIterator.next().toString(buffer);

        if (attrIterator.hasNext())
        {
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }

    buffer.append("')");
  }
}
