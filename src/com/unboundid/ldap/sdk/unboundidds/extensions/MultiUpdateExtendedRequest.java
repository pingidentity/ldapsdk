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
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.protocol.AddRequestProtocolOp;
import com.unboundid.ldap.protocol.DeleteRequestProtocolOp;
import com.unboundid.ldap.protocol.ExtendedRequestProtocolOp;
import com.unboundid.ldap.protocol.LDAPMessage;
import com.unboundid.ldap.protocol.ModifyDNRequestProtocolOp;
import com.unboundid.ldap.protocol.ModifyRequestProtocolOp;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPRequest;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
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
 * This class provides an implementation of an extended request that can be used
 * to send multiple update requests to the server in a single packet, optionally
 * processing them as a single atomic unit.
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
 * The OID for this request is 1.3.6.1.4.1.30221.2.6.17, and the value must have
 * the following encoding:
 * <BR><BR>
 * <PRE>
 *   MultiUpdateRequestValue ::= SEQUENCE {
 *        errorBehavior     ENUMERATED {
 *             atomic              (0),
 *             quitOnError         (1),
 *             continueOnError     (2),
 *             ... },
 *        requests          SEQUENCE OF SEQUENCE {
 *             updateOp     CHOICE {
 *                  modifyRequest     ModifyRequest,
 *                  addRequest        AddRequest,
 *                  delRequest        DelRequest,
 *                  modDNRequest      ModifyDNRequest,
 *                  extendedReq       ExtendedRequest,
 *                  ... },
 *             controls     [0] Controls OPTIONAL,
 *             ... },
 *        ... }
 * </PRE>
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the multi-update extended
 * request to create a new user entry and modify an existing group entry to add
 * the new user as a member:
 * <PRE>
 * MultiUpdateExtendedRequest multiUpdateRequest =
 *      new MultiUpdateExtendedRequest(
 *           MultiUpdateErrorBehavior.ABORT_ON_ERROR,
 *           new AddRequest(
 *                "dn: uid=new.user,ou=People,dc=example,dc=com",
 *                "objectClass: top",
 *                "objectClass: person",
 *                "objectClass: organizationalPerson",
 *                "objectClass: inetOrgPerson",
 *                "uid: new.user",
 *                "givenName: New",
 *                "sn: User",
 *                "cn: New User"),
 *           new ModifyRequest(
 *                "dn: cn=Test Group,ou=Groups,dc=example,dc=com",
 *                "changetype: modify",
 *                "add: member",
 *                "member: uid=new.user,ou=People,dc=example,dc=com"));
 *
 * MultiUpdateExtendedResult multiUpdateResult =
 *      (MultiUpdateExtendedResult)
 *      connection.processExtendedOperation(multiUpdateRequest);
 * if (multiUpdateResult.getResultCode() == ResultCode.SUCCESS)
 * {
 *   // The server successfully processed the multi-update request, although
 *   // this does not necessarily mean that any or all of the changes
 *   // contained in it were successful.  For that, we should look at the
 *   // changes applied and/or results element of the response.
 *   switch (multiUpdateResult.getChangesApplied())
 *   {
 *     case NONE:
 *       // There were no changes applied.  Based on the configuration of the
 *       // request, this means that the attempt to create the user failed
 *       // and there was no subsequent attempt to add that user to a group.
 *       break;
 *     case ALL:
 *       // Both parts of the update succeeded.  The user was created and
 *       // successfully added to a group.
 *       break;
 *     case PARTIAL:
 *       // At least one update succeeded, and at least one failed.  Based on
 *       // the configuration of the request, this means that the user was
 *       // successfully created but not added to the target group.
 *       break;
 *   }
 * }
 * else
 * {
 *   // The server encountered a failure while attempting to parse or process
 *   // the multi-update operation itself and did not attempt to process any
 *   // of the changes contained in the request.
 * }
 * </PRE>
 *
 * @see  MultiUpdateErrorBehavior
 * @see  MultiUpdateExtendedResult
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class MultiUpdateExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.17) for the multi-update extended request.
   */
  @NotNull public static final String MULTI_UPDATE_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.17";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6101686180473949142L;



  // The set of update requests to be processed.
  @NotNull private final List<LDAPRequest> requests;

  // The behavior to exhibit if an error is encountered during processing.
  @NotNull private final MultiUpdateErrorBehavior errorBehavior;



  /**
   * Creates a new multi-update extended request with the provided information.
   *
   * @param  errorBehavior  The behavior to exhibit if errors are encountered.
   *                        It must not be {@code null}.
   * @param  requests       The  set of requests to be processed.  It must not
   *                        be {@code null} or empty.  Only add, delete, modify,
   *                        modify DN, and certain extended requests (as
   *                        determined by the server) should be included.
   *
   * @throws  LDAPException  If the set of requests includes one or more invalid
   *                         request types.
   */
  public MultiUpdateExtendedRequest(
              @NotNull final MultiUpdateErrorBehavior errorBehavior,
              @NotNull final LDAPRequest... requests)
         throws LDAPException
  {
    this(errorBehavior, Arrays.asList(requests));
  }



  /**
   * Creates a new multi-update extended request with the provided information.
   *
   * @param  errorBehavior  The behavior to exhibit if errors are encountered.
   *                        It must not be {@code null}.
   * @param  requests       The  set of requests to be processed.  It must not
   *                        be {@code null} or empty.  Only add, delete, modify,
   *                        modify DN, and certain extended requests (as
   *                        determined by the server) should be included.  Each
   *                        request may include zero or more controls that
   *                        should apply only to that request.
   * @param  controls       The set of controls to be included in the
   *                        multi-update extended request.  It may be empty or
   *                        {@code null} if no extended request controls are
   *                        needed in the multi-update request.
   *
   * @throws  LDAPException  If the set of requests includes one or more invalid
   *                         request types.
   */
  public MultiUpdateExtendedRequest(
              @NotNull final MultiUpdateErrorBehavior errorBehavior,
              @NotNull final LDAPRequest[] requests,
              @Nullable final Control... controls)
         throws LDAPException
  {
    this(errorBehavior, Arrays.asList(requests), controls);
  }



  /**
   * Creates a new multi-update extended request with the provided information.
   *
   * @param  errorBehavior  The behavior to exhibit if errors are encountered.
   *                        It must not be {@code null}.
   * @param  requests       The  set of requests to be processed.  It must not
   *                        be {@code null} or empty.  Only add, delete, modify,
   *                        modify DN, and certain extended requests (as
   *                        determined by the server) should be included.  Each
   *                        request may include zero or more controls that
   *                        should apply only to that request.
   * @param  controls       The set of controls to be included in the
   *                        multi-update extended request.  It may be empty or
   *                        {@code null} if no extended request controls are
   *                        needed in the multi-update request.
   *
   * @throws  LDAPException  If the set of requests includes one or more invalid
   *                         request types.
   */
  public MultiUpdateExtendedRequest(
              @NotNull final MultiUpdateErrorBehavior errorBehavior,
              @NotNull final List<LDAPRequest> requests,
              @Nullable final Control... controls)
         throws LDAPException
  {
    super(MULTI_UPDATE_REQUEST_OID, encodeValue(errorBehavior, requests),
          controls);

    this.errorBehavior = errorBehavior;

    final ArrayList<LDAPRequest> requestList = new ArrayList<>(requests.size());
    for (final LDAPRequest r : requests)
    {
      switch (r.getOperationType())
      {
        case ADD:
        case DELETE:
        case MODIFY:
        case MODIFY_DN:
        case EXTENDED:
          requestList.add(r);
          break;
        default:
          throw new LDAPException(ResultCode.PARAM_ERROR,
               ERR_MULTI_UPDATE_REQUEST_INVALID_REQUEST_TYPE.get(
                    r.getOperationType().name()));
      }
    }
    this.requests = Collections.unmodifiableList(requestList);
  }



  /**
   * Creates a new multi-update extended request with the provided information.
   *
   * @param  errorBehavior  The behavior to exhibit if errors are encountered.
   *                        It must not be {@code null}.
   * @param  requests       The  set of requests to be processed.  It must not
   *                        be {@code null} or empty.  Only add, delete, modify,
   *                        modify DN, and certain extended requests (as
   *                        determined by the server) should be included.  Each
   *                        request may include zero or more controls that
   *                        should apply only to that request.
   * @param  encodedValue   The encoded representation of the value for this
   *                        request.
   * @param  controls       The set of controls to be included in the
   *                        multi-update extended request.  It may be empty or
   *                        {@code null} if no extended request controls are
   *                        needed in the multi-update request.
   */
  private MultiUpdateExtendedRequest(
               @NotNull final MultiUpdateErrorBehavior errorBehavior,
               @NotNull final List<LDAPRequest> requests,
               @NotNull final ASN1OctetString encodedValue,
               @Nullable final Control... controls)
  {
    super(MULTI_UPDATE_REQUEST_OID, encodedValue, controls);

    this.errorBehavior = errorBehavior;
    this.requests      = requests;
  }



  /**
   * Creates a new multi-update extended request from the provided generic
   * extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          multi-update extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public MultiUpdateExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_MULTI_UPDATE_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] ve =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();

      errorBehavior = MultiUpdateErrorBehavior.valueOf(
           ASN1Enumerated.decodeAsEnumerated(ve[0]).intValue());
      if (errorBehavior == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_MULTI_UPDATE_REQUEST_INVALID_ERROR_BEHAVIOR.get(
                  ASN1Enumerated.decodeAsEnumerated(ve[0]).intValue()));
      }

      final ASN1Element[] requestSequenceElements =
           ASN1Sequence.decodeAsSequence(ve[1]).elements();
      final ArrayList<LDAPRequest> rl =
           new ArrayList<>(requestSequenceElements.length);
      for (final ASN1Element rse : requestSequenceElements)
      {
        final Control[] controls;
        final ASN1Element[] requestElements =
             ASN1Sequence.decodeAsSequence(rse).elements();
        if (requestElements.length == 2)
        {
          controls = Control.decodeControls(
               ASN1Sequence.decodeAsSequence(requestElements[1]));
        }
        else
        {
          controls = StaticUtils.NO_CONTROLS;
        }

        switch (requestElements[0].getType())
        {
          case LDAPMessage.PROTOCOL_OP_TYPE_ADD_REQUEST:
            rl.add(AddRequestProtocolOp.decodeProtocolOp(
                 requestElements[0]).toAddRequest(controls));
            break;

          case LDAPMessage.PROTOCOL_OP_TYPE_DELETE_REQUEST:
            rl.add(DeleteRequestProtocolOp.decodeProtocolOp(
                 requestElements[0]).toDeleteRequest(controls));
            break;

          case LDAPMessage.PROTOCOL_OP_TYPE_EXTENDED_REQUEST:
            rl.add(ExtendedRequestProtocolOp.decodeProtocolOp(
                 requestElements[0]).toExtendedRequest(controls));
            break;

          case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_REQUEST:
            rl.add(ModifyRequestProtocolOp.decodeProtocolOp(
                 requestElements[0]).toModifyRequest(controls));
            break;

          case LDAPMessage.PROTOCOL_OP_TYPE_MODIFY_DN_REQUEST:
            rl.add(ModifyDNRequestProtocolOp.decodeProtocolOp(
                 requestElements[0]).toModifyDNRequest(controls));
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_MULTI_UPDATE_REQUEST_INVALID_OP_TYPE.get(
                      StaticUtils.toHex(requestElements[0].getType())));
        }
      }

      requests = Collections.unmodifiableList(rl);
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
           ERR_MULTI_UPDATE_REQUEST_CANNOT_DECODE_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Generates an ASN.1 octet string suitable for use as the value of a
   * multi-update extended request.
   *
   * @param  errorBehavior  The behavior to exhibit if errors are encountered.
   *                        It must not be {@code null}.
   * @param  requests       The  set of requests to be processed.  It must not
   *                        be {@code null} or empty.  Only add, delete, modify,
   *                        modify DN, and certain extended requests (as
   *                        determined by the server) should be included.  Each
   *                        request may include zero or more controls that
   *                        should apply only to that request.
   *
   * @return  An ASN.1 octet string suitable for use as the value of a
   *          multi-update extended request.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
                      @NotNull final MultiUpdateErrorBehavior errorBehavior,
                      @NotNull final List<LDAPRequest> requests)
  {
    final ArrayList<ASN1Element> requestElements =
         new ArrayList<>(requests.size());
    for (final LDAPRequest r : requests)
    {
      final ArrayList<ASN1Element> rsElements = new ArrayList<>(2);
      switch (r.getOperationType())
      {
        case ADD:
          rsElements.add(((AddRequest) r).encodeProtocolOp());
          break;
        case DELETE:
          rsElements.add(((DeleteRequest) r).encodeProtocolOp());
          break;
        case MODIFY:
          rsElements.add(((ModifyRequest) r).encodeProtocolOp());
          break;
        case MODIFY_DN:
          rsElements.add(((ModifyDNRequest) r).encodeProtocolOp());
          break;
        case EXTENDED:
          rsElements.add(((ExtendedRequest) r).encodeProtocolOp());
          break;
      }

      if (r.hasControl())
      {
        rsElements.add(Control.encodeControls(r.getControls()));
      }

      requestElements.add(new ASN1Sequence(rsElements));
    }

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated(errorBehavior.intValue()),
         new ASN1Sequence(requestElements));
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public MultiUpdateExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new MultiUpdateExtendedResult(extendedResponse);
  }



  /**
   * Retrieves the behavior to exhibit if errors are encountered.
   *
   * @return  The behavior to exhibit if errors are encountered.
   */
  @NotNull()
  public MultiUpdateErrorBehavior getErrorBehavior()
  {
    return errorBehavior;
  }



  /**
   *
   * Retrieves the set of requests to be processed.
   *
   * @return  The set of requests to be processed.
   */
  @NotNull()
  public List<LDAPRequest> getRequests()
  {
    return requests;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public MultiUpdateExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public MultiUpdateExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final MultiUpdateExtendedRequest r =
         new MultiUpdateExtendedRequest(errorBehavior, requests,
              getValue(), controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_MULTI_UPDATE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("MultiUpdateExtendedRequest(errorBehavior=");
    buffer.append(errorBehavior.name());
    buffer.append(", requests={");

    final Iterator<LDAPRequest> iterator = requests.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append('}');

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
