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



import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control which may be used to request that the
 * server return resource limit information for the authenticated user in the
 * response to a successful bind operation.  Resource limits that may be
 * returned include custom size limit, time limit, idle time limit, lookthrough
 * limit, equivalent authorization user DN, client connection policy name, and
 * privilege names.
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
 * The criticality for this control may be either {@code true} or {@code false}.
 * It may optionally have a value, although it should only have a value if the
 * server advertises OID "1.3.6.1.4.1.30221.2.12.6"
 * ({@link #EXCLUDE_GROUPS_FEATURE_OID}) in the supportedFeatures attribute of
 * its root DSE.  The {@link #serverAdvertisesExcludeGroupsFeature} method can
 * help clients make that determination.
 * <BR><BR>
 * If the control does have a value, then it should use the following encoding:
 * <PRE>
 *   GetUserResourceLimitsRequest ::= SEQUENCE {
 *        excludeGroups     [0] BOOLEAN DEFAULT FALSE,
 *        ... }
 * </PRE>
 * <BR><BR>
 * If the control does not have a value, then the server will assume the default
 * behavior for all elements that would be in the value.
 *
 * @see GetUserResourceLimitsResponseControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetUserResourceLimitsRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.25) for the get user resource limits request
   * control.
   */
  @NotNull public static final String GET_USER_RESOURCE_LIMITS_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.25";



  /**
   * The OID (1.3.6.1.4.1.30221.2.12.6) for the supportedFeature value that a
   * server should advertise in its root DSE if it supports a value indicating
   * that the server allows the control to include a value that indicates it
   * should omit group membership information from the response control.
   */
  @NotNull public static final String EXCLUDE_GROUPS_FEATURE_OID =
       "1.3.6.1.4.1.30221.2.12.6";



  /**
   * The BER type for the request value element that indicates whether groups
   * should be excluded from the response control.
   */
  private static final byte TYPE_EXCLUDE_GROUPS = (byte) 0x80;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4349321415426346390L;



  // Indicates whether the server should exclude information about group
  // membership from the response control.
  private final boolean excludeGroups;



  /**
   * Creates a new get user resource limits request control.  It will not be
   * marked critical.
   */
  public GetUserResourceLimitsRequestControl()
  {
    this(false);
  }



  /**
   * Creates a new get user resource limits request control with the specified
   * criticality.
   *
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   */
  public GetUserResourceLimitsRequestControl(final boolean isCritical)
  {
    this(false, false);
  }



  /**
   * Creates a new get user resource limits request control with the specified
   * criticality.
   *
   * @param  isCritical     Indicates whether this control should be marked
   *                        critical.
   * @param  excludeGroups  Indicates whether the server should exclude
   *                        information about group membership from the response
   *                        control.  This should generally only be {@code true}
   *                        if the client has confirmed that the server supports
   *                        this ability, which may be determined using the
   *                        {@link #serverAdvertisesExcludeGroupsFeature}
   *                        method.
   */
  public GetUserResourceLimitsRequestControl(final boolean isCritical,
                                             final boolean excludeGroups)
  {
    super(GET_USER_RESOURCE_LIMITS_REQUEST_OID, isCritical,
         encodeValue(excludeGroups));

    this.excludeGroups = excludeGroups;
  }



  /**
   * Encodes a value for this control, if appropriate.
   *
   * @param  excludeGroups  Indicates whether the server should exclude
   *                        information about group membership from the response
   *                        control.  This should generally only be {@code true}
   *                        if the client has confirmed that the server supports
   *                        this ability, which may be determined using the
   *                        {@link #serverAdvertisesExcludeGroupsFeature}
   *                        method.
   *
   * @return  A value for this control, or {@code null} if no value is needed.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(final boolean excludeGroups)
  {
    if (excludeGroups)
    {
      return new ASN1OctetString(
           new ASN1Sequence(
                new ASN1Boolean(TYPE_EXCLUDE_GROUPS, true)).encode());
    }

    return null;
  }



  /**
   * Creates a new get user resource limits request control which is decoded
   * from the provided generic control.
   *
   * @param  control  The generic control to be decoded as a get user resource
   *                  limits request control.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a get
   *                         user resource limits request control.
   */
  public GetUserResourceLimitsRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      excludeGroups = false;
      return;
    }

    try
    {
      boolean excludeGroupsMutable = false;
      final ASN1Sequence valueSequence =
           ASN1Sequence.decodeAsSequence(value.getValue());
      for (final ASN1Element e : valueSequence.elements())
      {
        switch (e.getType())
        {
          case TYPE_EXCLUDE_GROUPS:
            excludeGroupsMutable =
                 ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
        }
      }

      excludeGroups = excludeGroupsMutable;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_USER_RESOURCE_LIMITS_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Indicates whether the control requests that the server exclude information
   * about group membership from the corresponding response control.
   *
   * @return  {@code true} if the server should exclude information about group
   *          membership from the response control, or {@code false} if not.
   */
  public boolean excludeGroups()
  {
    return excludeGroups;
  }



  /**
   * Indicates whether the provided root DSE advertises support for a feature
   * that indicates it is acceptable for the client to request that the server
   * omit group membership information from the corresponding response
   * control.
   *
   * @param  rootDSE  An object with information from the root DSE of the server
   *                  for which to make the determination.  It must not be
   *                  {@code null}.
   *
   * @return  {@code true} if the provided root DSE object indicates that the
   *          server supports clients requesting to exclude group membership
   *          information from the response control, or {@code false} if not.
   */
  public static boolean serverAdvertisesExcludeGroupsFeature(
              @NotNull final RootDSE rootDSE)
  {
    return rootDSE.supportsFeature(EXCLUDE_GROUPS_FEATURE_OID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GET_USER_RESOURCE_LIMITS_REQUEST.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetUserResourceLimitsRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", excludeGroups=");
    buffer.append(excludeGroups);
    buffer.append(')');
  }
}
