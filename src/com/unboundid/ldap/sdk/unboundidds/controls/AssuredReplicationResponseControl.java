/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
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
 * This class provides an implementation of an LDAP control that can be included
 * in add, bind, modify, modify DN, and certain extended responses to provide
 * information about the result of replication assurance processing for that
 * operation.
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
 * The OID for this control is 1.3.6.1.4.1.30221.2.5.29.  It will have a
 * criticality of FALSE, and will have a value with the following encoding:
 * <PRE>
 *   AssuredReplicationResponse ::= SEQUENCE {
 *        localLevel                   [0] LocalLevel OPTIONAL,
 *        localAssuranceSatisfied      [1] BOOLEAN,
 *        localAssuranceMessage        [2] OCTET STRING OPTIONAL,
 *        remoteLevel                  [3] RemoteLevel OPTIONAL,
 *        remoteAssuranceSatisfied     [4] BOOLEAN,
 *        remoteAssuranceMessage       [5] OCTET STRING OPTIONAL,
 *        csn                          [6] OCTET STRING OPTIONAL,
 *        serverResults                [7] SEQUENCE OF ServerResult OPTIONAL,
 *        ... }
 *
 *   ServerResult ::= SEQUENCE {
 *        resultCode              [0] ENUMERATED {
 *             complete           (0),
 *             timeout            (1),
 *             conflict           (2),
 *             serverShutdown     (3),
 *             unavailable        (4),
 *             duplicate          (5),
 *             ... },
 *        replicationServerID     [1] INTEGER OPTIONAL,
 *        replicaID               [2] INTEGER OPTIONAL,
 *        ... }
 * </PRE>
 *
 * @see  AssuredReplicationRequestControl
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class AssuredReplicationResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.29) for the assured replication response
   * control.
   */
  @NotNull public static final String ASSURED_REPLICATION_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.29";


  /**
   * The BER type for the local level element.
   */
  private static final byte TYPE_LOCAL_LEVEL = (byte) 0x80;


  /**
   * The BER type for the local assurance satisfied element.
   */
  private static final byte TYPE_LOCAL_SATISFIED = (byte) 0x81;


  /**
   * The BER type for the local message element.
   */
  private static final byte TYPE_LOCAL_MESSAGE = (byte) 0x82;


  /**
   * The BER type for the remote level element.
   */
  private static final byte TYPE_REMOTE_LEVEL = (byte) 0x83;


  /**
   * The BER type for the remote assurance satisfied element.
   */
  private static final byte TYPE_REMOTE_SATISFIED = (byte) 0x84;


  /**
   * The BER type for the remote message element.
   */
  private static final byte TYPE_REMOTE_MESSAGE = (byte) 0x85;


  /**
   * The BER type for the CSN element.
   */
  private static final byte TYPE_CSN = (byte) 0x86;


  /**
   * The BER type for the server results element.
   */
  private static final byte TYPE_SERVER_RESULTS = (byte) 0xA7;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4521456074629871607L;



  // The assurance level for local processing.
  @Nullable private final AssuredReplicationLocalLevel localLevel;

  // The assurance level for remote processing.
  @Nullable private final AssuredReplicationRemoteLevel remoteLevel;

  // Indicates whether the desired local assurance has been satisfied.
  private final boolean localAssuranceSatisfied;

  // Indicates whether the desired remote assurance has been satisfied.
  private final boolean remoteAssuranceSatisfied;

  // The results from individual replication and/or directory servers.
  @NotNull private final List<AssuredReplicationServerResult> serverResults;

  // The replication change sequence number for the associated operation.
  @Nullable private final String csn;

  // An optional message with additional information about local assurance
  // processing.
  @Nullable private final String localAssuranceMessage;

  // An optional message with additional information about local assurance
  // processing.
  @Nullable private final String remoteAssuranceMessage;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  AssuredReplicationResponseControl()
  {
    localLevel = null;
    localAssuranceSatisfied = false;
    localAssuranceMessage = null;
    remoteLevel = null;
    remoteAssuranceSatisfied = false;
    remoteAssuranceMessage = null;
    csn = null;
    serverResults = null;
  }



  /**
   * Creates a new assured replication response control with the provided
   * information.
   *
   * @param  localLevel                The local assurance level selected by the
   *                                   server for the associated operation.  It
   *                                   may be {@code null} if this is not
   *                                   available.
   * @param  localAssuranceSatisfied   Indicates whether the desired local level
   *                                   of assurance is known to have been
   *                                   satisfied.
   * @param  localAssuranceMessage     An optional message providing additional
   *                                   information about local assurance
   *                                   processing.  This may be {@code null} if
   *                                   no additional message is needed.
   * @param  remoteLevel               The remote assurance level selected by
   *                                   the server for the associated operation.
   *                                   It may be {@code null} if this is not
   *                                   available.
   * @param  remoteAssuranceSatisfied  Indicates whether the desired remote
   *                                   level of assurance is known to have been
   *                                   satisfied.
   * @param  remoteAssuranceMessage    An optional message providing additional
   *                                   information about remote assurance
   *                                   processing.  This may be {@code null} if
   *                                   no additional message is needed.
   * @param  csn                       The change sequence number (CSN) that has
   *                                   been assigned to the associated
   *                                   operation.  It may be {@code null} if no
   *                                   CSN is available.
   * @param  serverResults             The set of individual results from the
   *                                   local and/or remote replication servers
   *                                   and/or directory servers used in
   *                                   assurance processing.  This may be
   *                                   {@code null} or empty if no server
   *                                   results are available.
   */
  public AssuredReplicationResponseControl(
       @Nullable final AssuredReplicationLocalLevel localLevel,
       final boolean localAssuranceSatisfied,
       @Nullable final String localAssuranceMessage,
       @Nullable final AssuredReplicationRemoteLevel remoteLevel,
       final boolean remoteAssuranceSatisfied,
       @Nullable final String remoteAssuranceMessage,
       @Nullable final String csn,
       @Nullable final Collection<AssuredReplicationServerResult> serverResults)
  {
    super(ASSURED_REPLICATION_RESPONSE_OID, false,
         encodeValue(localLevel, localAssuranceSatisfied,
              localAssuranceMessage, remoteLevel, remoteAssuranceSatisfied,
              remoteAssuranceMessage, csn, serverResults));

    this.localLevel               = localLevel;
    this.localAssuranceSatisfied  = localAssuranceSatisfied;
    this.localAssuranceMessage    = localAssuranceMessage;
    this.remoteLevel              = remoteLevel;
    this.remoteAssuranceSatisfied = remoteAssuranceSatisfied;
    this.remoteAssuranceMessage   = remoteAssuranceMessage;
    this.csn                      = csn;

    if (serverResults == null)
    {
      this.serverResults = Collections.emptyList();
    }
    else
    {
      this.serverResults = Collections.unmodifiableList(
           new ArrayList<>(serverResults));
    }
  }



  /**
   * Creates a new assured replication response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as an
   *                         assured replication response control.
   */
  public AssuredReplicationResponseControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ASSURED_REPLICATION_RESPONSE_NO_VALUE.get());
    }

    AssuredReplicationLocalLevel         lLevel     = null;
    Boolean                              lSatisfied = null;
    String                               lMessage   = null;
    AssuredReplicationRemoteLevel        rLevel     = null;
    Boolean                              rSatisfied = null;
    String                               rMessage   = null;
    String                               seqNum     = null;
    List<AssuredReplicationServerResult> sResults   = Collections.emptyList();

    try
    {
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(value.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_LOCAL_LEVEL:
            int intValue = ASN1Enumerated.decodeAsEnumerated(e).intValue();
            lLevel = AssuredReplicationLocalLevel.valueOf(intValue);
            if (lLevel == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ASSURED_REPLICATION_RESPONSE_INVALID_LOCAL_LEVEL.get(
                        intValue));
            }
            break;

          case TYPE_LOCAL_SATISFIED:
            lSatisfied = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;

          case TYPE_LOCAL_MESSAGE:
            lMessage = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          case TYPE_REMOTE_LEVEL:
            intValue = ASN1Enumerated.decodeAsEnumerated(e).intValue();
            rLevel = AssuredReplicationRemoteLevel.valueOf(intValue);
            if (lLevel == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_ASSURED_REPLICATION_RESPONSE_INVALID_REMOTE_LEVEL.get(
                        intValue));
            }
            break;

          case TYPE_REMOTE_SATISFIED:
            rSatisfied = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;

          case TYPE_REMOTE_MESSAGE:
            rMessage = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          case TYPE_CSN:
            seqNum = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          case TYPE_SERVER_RESULTS:
            final ASN1Element[] srElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            final ArrayList<AssuredReplicationServerResult> srList =
                 new ArrayList<>(srElements.length);
            for (final ASN1Element srElement : srElements)
            {
              try
              {
                srList.add(AssuredReplicationServerResult.decode(srElement));
              }
              catch (final Exception ex)
              {
                Debug.debugException(ex);
                throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_ASSURED_REPLICATION_RESPONSE_ERROR_DECODING_SR.get(
                          StaticUtils.getExceptionMessage(ex)),
                     ex);
              }
            }
            sResults = Collections.unmodifiableList(srList);
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_ASSURED_REPLICATION_RESPONSE_UNEXPECTED_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }
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
           ERR_ASSURED_REPLICATION_RESPONSE_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (lSatisfied == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ASSURED_REPLICATION_RESPONSE_NO_LOCAL_SATISFIED.get());
    }

    if (rSatisfied == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_ASSURED_REPLICATION_RESPONSE_NO_REMOTE_SATISFIED.get());
    }

    localLevel               = lLevel;
    localAssuranceSatisfied  = lSatisfied;
    localAssuranceMessage    = lMessage;
    remoteLevel              = rLevel;
    remoteAssuranceSatisfied = rSatisfied;
    remoteAssuranceMessage   = rMessage;
    csn                      = seqNum;
    serverResults            = sResults;
  }



  /**
   * Encodes the provided information to an ASN.1 octet string suitable for
   * use as an assured replication response control value.
   *
   * @param  localLevel                The local assurance level selected by the
   *                                   server for the associated operation.  It
   *                                   may be {@code null} if this is not
   *                                   available.
   * @param  localAssuranceSatisfied   Indicates whether the desired local level
   *                                   of assurance is known to have been
   *                                   satisfied.
   * @param  localAssuranceMessage     An optional message providing additional
   *                                   information about local assurance
   *                                   processing.  This may be {@code null} if
   *                                   no additional message is needed.
   * @param  remoteLevel               The remote assurance level selected by
   *                                   the server for the associated operation.
   *                                   It may be {@code null} if this is not
   *                                   available.
   * @param  remoteAssuranceSatisfied  Indicates whether the desired remote
   *                                   level of assurance is known to have been
   *                                   satisfied.
   * @param  remoteAssuranceMessage    An optional message providing additional
   *                                   information about remote assurance
   *                                   processing.  This may be {@code null} if
   *                                   no additional message is needed.
   * @param  csn                       The change sequence number (CSN) that has
   *                                   been assigned to the associated
   *                                   operation.  It may be {@code null} if no
   *                                   CSN is available.
   * @param  serverResults             The set of individual results from the
   *                                   local and/or remote replication servers
   *                                   and/or directory servers used in
   *                                   assurance processing.  This may be
   *                                   {@code null} or empty if no server
   *                                   results are available.
   *
   * @return  The ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
       @Nullable final AssuredReplicationLocalLevel localLevel,
       final boolean localAssuranceSatisfied,
       @Nullable final String localAssuranceMessage,
       @Nullable final AssuredReplicationRemoteLevel remoteLevel,
       final boolean remoteAssuranceSatisfied,
       @Nullable final String remoteAssuranceMessage,
       @Nullable final String csn,
       @Nullable final Collection<AssuredReplicationServerResult> serverResults)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(8);

    if (localLevel != null)
    {
      elements.add(new ASN1Enumerated(TYPE_LOCAL_LEVEL, localLevel.intValue()));
    }

    elements.add(new ASN1Boolean(TYPE_LOCAL_SATISFIED,
         localAssuranceSatisfied));

    if (localAssuranceMessage != null)
    {
      elements.add(new ASN1OctetString(TYPE_LOCAL_MESSAGE,
           localAssuranceMessage));
    }

    if (remoteLevel != null)
    {
      elements.add(new ASN1Enumerated(TYPE_REMOTE_LEVEL,
           remoteLevel.intValue()));
    }

    elements.add(new ASN1Boolean(TYPE_REMOTE_SATISFIED,
         remoteAssuranceSatisfied));

    if (remoteAssuranceMessage != null)
    {
      elements.add(new ASN1OctetString(TYPE_REMOTE_MESSAGE,
           remoteAssuranceMessage));
    }

    if (csn != null)
    {
      elements.add(new ASN1OctetString(TYPE_CSN, csn));
    }

    if ((serverResults !=  null) && (! serverResults.isEmpty()))
    {
      final ArrayList<ASN1Element> srElements =
           new ArrayList<>(serverResults.size());
      for (final AssuredReplicationServerResult r : serverResults)
      {
        srElements.add(r.encode());
      }
      elements.add(new ASN1Sequence(TYPE_SERVER_RESULTS, srElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public AssuredReplicationResponseControl decodeControl(
              @NotNull final String oid, final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new AssuredReplicationResponseControl(oid, isCritical, value);
  }



  /**
   * Extracts an assured replication response control from the provided LDAP
   * result.  If there are multiple assured replication response controls
   * included in the result, then only the first will be returned.
   *
   * @param  result  The LDAP result from which to retrieve the assured
   *                 replication response control.
   *
   * @return  The assured replication response control contained in the provided
   *          LDAP result, or {@code null} if the result did not contain an
   *          assured replication response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the assured replication response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static AssuredReplicationResponseControl get(
                     @NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c =
         result.getResponseControl(ASSURED_REPLICATION_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof AssuredReplicationResponseControl)
    {
      return (AssuredReplicationResponseControl) c;
    }
    else
    {
      return new AssuredReplicationResponseControl(c.getOID(), c.isCritical(),
           c.getValue());
    }
  }



  /**
   * Extracts all assured replication response controls from the provided LDAP
   * result.
   *
   * @param  result  The LDAP result from which to retrieve the assured
   *                 replication response controls.
   *
   * @return  A list containing the assured replication response controls
   *          contained in the provided LDAP result, or an empty list if the
   *          result did not contain any assured replication response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode any assured replication response control
   *                         contained in the provided result.
   */
  @NotNull()
  public static List<AssuredReplicationResponseControl> getAll(
                     @NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control[] controls = result.getResponseControls();
    final ArrayList<AssuredReplicationResponseControl> decodedControls =
         new ArrayList<>(controls.length);
    for (final Control c : controls)
    {
      if (c.getOID().equals(ASSURED_REPLICATION_RESPONSE_OID))
      {
        if (c instanceof AssuredReplicationResponseControl)
        {
          decodedControls.add((AssuredReplicationResponseControl) c);
        }
        else
        {
          decodedControls.add(new AssuredReplicationResponseControl(c.getOID(),
               c.isCritical(), c.getValue()));
        }
      }
    }

    return Collections.unmodifiableList(decodedControls);
  }



  /**
   * Retrieves the local assurance level selected by the server for the
   * associated operation, if available.
   *
   * @return  The local assurance level selected by the server for the
   *          associated operation, or {@code null} if this is not available.
   */
  @Nullable()
  public AssuredReplicationLocalLevel getLocalLevel()
  {
    return localLevel;
  }



  /**
   * Indicates whether the desired local level of assurance is known to have
   * been satisfied.
   *
   * @return  {@code true} if the desired local level of assurance is known to
   *          have been satisfied, or {@code false} if not.
   */
  public boolean localAssuranceSatisfied()
  {
    return localAssuranceSatisfied;
  }



  /**
   * Retrieves a message with additional information about local assurance
   * processing, if available.
   *
   * @return  A message with additional information about local assurance
   *          processing, or {@code null} if none is available.
   */
  @Nullable()
  public String getLocalAssuranceMessage()
  {
    return localAssuranceMessage;
  }



  /**
   * Retrieves the remote assurance level selected by the server for the
   * associated operation, if available.
   *
   * @return  The remote assurance level selected by the server for the
   *          associated operation, or {@code null} if the remote assurance
   *          level is not available.
   */
  @Nullable()
  public AssuredReplicationRemoteLevel getRemoteLevel()
  {
    return remoteLevel;
  }



  /**
   * Indicates whether the desired remote level of assurance is known to have
   * been satisfied.
   *
   * @return  {@code true} if the desired remote level of assurance is known to
   *          have been satisfied, or {@code false} if not.
   */
  public boolean remoteAssuranceSatisfied()
  {
    return remoteAssuranceSatisfied;
  }



  /**
   * Retrieves a message with additional information about remote assurance
   * processing, if available.
   *
   * @return  A message with additional information about remote assurance
   *          processing, or {@code null} if none is available.
   */
  @Nullable()
  public String getRemoteAssuranceMessage()
  {
    return remoteAssuranceMessage;
  }



  /**
   * Retrieves the replication change sequence number (CSN) assigned to the
   * associated operation, if available.
   *
   * @return  The replication CSN assigned to the associated operation, or
   *          {@code null} if the CSN is not available.
   */
  @Nullable()
  public String getCSN()
  {
    return csn;
  }



  /**
   * Retrieves a list of the results from individual replication servers and/or
   * directory servers used in assurance processing.  It may be empty if no
   * server results are available.
   *
   * @return  A list of the results from individual replication servers and/or
   *          directory servers used in assurance processing.
   */
  @NotNull()
  public List<AssuredReplicationServerResult> getServerResults()
  {
    return serverResults;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_ASSURED_REPLICATION_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("AssuredReplicationResponseControl(isCritical=");
    buffer.append(isCritical());

    if (localLevel != null)
    {
      buffer.append(", localLevel=");
      buffer.append(localLevel.name());
    }

    buffer.append(", localAssuranceSatisfied=");
    buffer.append(localAssuranceSatisfied);

    if (localAssuranceMessage != null)
    {
      buffer.append(", localMessage='");
      buffer.append(localAssuranceMessage);
      buffer.append('\'');
    }

    if (remoteLevel != null)
    {
      buffer.append(", remoteLevel=");
      buffer.append(remoteLevel.name());
    }

    buffer.append(", remoteAssuranceSatisfied=");
    buffer.append(remoteAssuranceSatisfied);

    if (remoteAssuranceMessage != null)
    {
      buffer.append(", remoteMessage='");
      buffer.append(remoteAssuranceMessage);
      buffer.append('\'');
    }

    if (csn != null)
    {
      buffer.append(", csn='");
      buffer.append(csn);
      buffer.append('\'');
    }

    if ((serverResults != null) && (! serverResults.isEmpty()))
    {
      buffer.append(", serverResults={");

      final Iterator<AssuredReplicationServerResult> iterator =
           serverResults.iterator();
      while (iterator.hasNext())
      {
        if (iterator.hasNext())
        {
          iterator.next().toString(buffer);
          buffer.append(", ");
        }
      }

      buffer.append('}');
    }

    buffer.append(')');
  }
}
