/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener.interceptor;



import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.Set;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.AddRequest;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.CompareRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DeleteRequest;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.GenericSASLBindRequest;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ModifyDNRequest;
import com.unboundid.ldap.sdk.ReadOnlyLDAPRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;



/**
 * This class provides an implementation of an in-memory operation interceptor
 * that uses request controls to indicate what behavior it should exhibit.  The
 * request control OID should be "1.2.3.4", and the control value should be the
 * name of one of the {@link TransformType} values.  Multiple controls may be
 * included in a single request to have multiple transformations applied.
 */
public final class ControlBasedOperationInterceptor
       extends InMemoryOperationInterceptor
{
  /**
   * The OID that should be used for the control that specifies a transformation
   * type.
   */
  static final String TRANSFORM_CONTROL_OID = "1.2.3.4";



  /**
   * The OID that will be used for the intermediate response object that is to
   * be injected into an operation.
   */
  static final String INTERMEDIATE_RESPONSE_OID = "1.2.3.5";



  /**
   * The OID that will be used for the unsolicited notification object that is
   * to be injected into an operation.
   */
  static final String UNSOLICITED_NOTIFICATION_OID = "1.2.3.6";



  /**
   * The state key that will be used to store the set of transformation types.
   */
  private static final String STATE_KEY_TRANSFORM_TYPES =
       ControlBasedOperationInterceptor.class.getName() + ".transformTypes";



  /**
   * Creates a new instance of this operation interceptor.
   */
  public ControlBasedOperationInterceptor()
  {
    // No implementation required.
  }



  /**
   * The set of transformation types that may be applied.  Each may be included
   * in a request with an OID of {@link #TRANSFORM_CONTROL_OID} and a value that
   * is the string returned by the {@code name()} method of the corresponding
   * enum value.
   */
  enum TransformType
  {
    /**
     * Indicates that the request should be rejected with an exception.
     */
    REJECT_REQUEST,

    /**
     * Indicates that a runtime exception should be thrown during request
     * processing.
     */
    REQUEST_RUNTIME_EXCEPTION,

    /**
     * Indicates that the result should be replaced with an error result.
     */
    ERROR_RESULT,

    /**
     * Indicates that a runtime exception should be thrown during result
     * processing.
     */
    RESULT_RUNTIME_EXCEPTION,

    /**
     * Indicates that the request target DN should be replaced with
     * "dc=example,dc=com".
     */
    ALTER_DN,

    /**
     * Indicates that any search result entries should be suppressed rather than
     * being returned to the client.
     */
    SUPPRESS_ENTRY,

    /**
     * Indicates that any search result entries to be returned should have their
     * DNs altered.
     */
    ALTER_ENTRY,

    /**
     * Indicates that a new search result entry should be injected into the
     * response to send to the client.
     */
    INJECT_ENTRY,

    /**
     * Indicates that a runtime exception should be thrown during search entry
     * processing.
     */
    ENTRY_RUNTIME_EXCEPTION,

    /**
     * Indicates that any search result references should be suppressed rather
     * than being returned to the client.
     */
    SUPPRESS_REFERENCE,

    /**
     * Indicates that any search result references to be returned should have
     * the DNs in their LDAP URLs altered.
     */
    ALTER_REFERENCE,

    /**
     * Indicates that a new search result reference should be injected into the
     * response to send to the client.
     */
    INJECT_REFERENCE,

    /**
     * Indicates that a runtime exception should be thrown during search
     * reference processing.
     */
    REFERENCE_RUNTIME_EXCEPTION,

    /**
     * Indicates that any intermediate responses should be suppressed rather
     * than being returned to the client.
     */
    SUPPRESS_INTERMEDIATE_RESPONSE,

    /**
     * Indicates that any intermediate responses should be altered before they
     * are returned to the client.
     */
    ALTER_INTERMEDIATE_RESPONSE,

    /**
     * Indicates that a new intermediate response should be injected into the
     * response to send to the client.
     */
    INJECT_INTERMEDIATE_RESPONSE,

    /**
     * Indicates that a runtime exception should be thrown during intermediate
     * response processing.
     */
    INTERMEDIATE_RESPONSE_RUNTIME_EXCEPTION,

    /**
     * Indicates that a new unsolicited notification should be injected into the
     * response to send to the client.
     */
    INJECT_UNSOLICITED_NOTIFICATION
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processAddRequest(final InMemoryInterceptedAddRequest request)
         throws LDAPException
  {
    final ObjectPair<Set<TransformType>,Control[]> transformationData =
         getTransformTypes(request.getRequest());

    // If there are no transformation types to apply, then return without doing
    // anything.
    final Set<TransformType> transformTypes =
         transformationData.getFirst();
    if (transformTypes.isEmpty())
    {
      return;
    }


    // Store the set of transformation types in the operation state for any
    // necessary result processing.
    request.setProperty(STATE_KEY_TRANSFORM_TYPES, transformTypes);


    // Update the request to remove the transformation controls.
    final Control[] remainingControls = transformationData.getSecond();
    final AddRequest addRequest =
         request.getRequest().duplicate(remainingControls);


    // Apply any necessary transformations to the request.
    if (transformTypes.contains(TransformType.REJECT_REQUEST))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           "Rejected by transformation control");
    }

    if (transformTypes.contains(TransformType.REQUEST_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(TransformType.ALTER_DN))
    {
      addRequest.setDN("ou=altered,dc=example,dc=com");
    }

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        request.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Request")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        request.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Request", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }


    // Update the add request to be processed.
    request.setRequest(addRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processAddResult(final InMemoryInterceptedAddResult result)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         result.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        result.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Response")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        result.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Result", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.ERROR_RESULT))
    {
      result.setResult(new LDAPResult(result.getMessageID(),
           ResultCode.UNWILLING_TO_PERFORM,
           "Error result by transformation", null, StaticUtils.NO_STRINGS,
           StaticUtils.NO_CONTROLS));
    }

    if (transformTypes.contains(TransformType.RESULT_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processSimpleBindRequest(
                   final InMemoryInterceptedSimpleBindRequest request)
         throws LDAPException
  {
    final ObjectPair<Set<TransformType>,Control[]> transformationData =
         getTransformTypes(request.getRequest());

    // If there are no transformation types to apply, then return without doing
    // anything.
    final Set<TransformType> transformTypes =
         transformationData.getFirst();
    if (transformTypes.isEmpty())
    {
      return;
    }


    // Store the set of transformation types in the operation state for any
    // necessary result processing.
    request.setProperty(STATE_KEY_TRANSFORM_TYPES, transformTypes);


    // Update the request to remove the transformation controls.
    final Control[] remainingControls = transformationData.getSecond();
    SimpleBindRequest bindRequest =
         request.getRequest().duplicate(remainingControls);


    // Apply any necessary transformations to the request.
    if (transformTypes.contains(TransformType.REJECT_REQUEST))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           "Rejected by transformation control");
    }

    if (transformTypes.contains(TransformType.REQUEST_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(TransformType.ALTER_DN))
    {
      final long responseTimeout = bindRequest.getResponseTimeoutMillis(null);
      bindRequest = new SimpleBindRequest("ou=altered,dc=example,dc=com",
           bindRequest.getPassword().getValue(), bindRequest.getControls());
      bindRequest.setResponseTimeoutMillis(responseTimeout);
    }

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        request.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Request")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        request.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Request", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }


    // Update the add request to be processed.
    request.setRequest(bindRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processSimpleBindResult(
                   final InMemoryInterceptedSimpleBindResult result)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         result.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        result.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Response")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        result.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Result", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.ERROR_RESULT))
    {
      result.setResult(new BindResult(result.getMessageID(),
           ResultCode.UNWILLING_TO_PERFORM,
           "Error result by transformation", null, StaticUtils.NO_STRINGS,
           StaticUtils.NO_CONTROLS, null));
    }

    if (transformTypes.contains(TransformType.RESULT_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processSASLBindRequest(
                   final InMemoryInterceptedSASLBindRequest request)
         throws LDAPException
  {
    final ObjectPair<Set<TransformType>,Control[]> transformationData =
         getTransformTypes(request.getRequest());

    // If there are no transformation types to apply, then return without doing
    // anything.
    final Set<TransformType> transformTypes =
         transformationData.getFirst();
    if (transformTypes.isEmpty())
    {
      return;
    }


    // Store the set of transformation types in the operation state for any
    // necessary result processing.
    request.setProperty(STATE_KEY_TRANSFORM_TYPES, transformTypes);


    // Update the request to remove the transformation controls.
    final Control[] remainingControls = transformationData.getSecond();
    GenericSASLBindRequest bindRequest =
         request.getRequest().duplicate(remainingControls);


    // Apply any necessary transformations to the request.
    if (transformTypes.contains(TransformType.REJECT_REQUEST))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           "Rejected by transformation control");
    }

    if (transformTypes.contains(TransformType.REQUEST_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(TransformType.ALTER_DN))
    {
      final long responseTimeout = bindRequest.getResponseTimeoutMillis(null);
      bindRequest = new GenericSASLBindRequest("ou=altered,dc=example,dc=com",
           bindRequest.getSASLMechanismName(), bindRequest.getCredentials(),
           bindRequest.getControls());
      bindRequest.setResponseTimeoutMillis(responseTimeout);
    }

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        request.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Request")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        request.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Request", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }


    // Update the add request to be processed.
    request.setRequest(bindRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processSASLBindResult(
                   final InMemoryInterceptedSASLBindResult result)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         result.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        result.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Response")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        result.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Result", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.ERROR_RESULT))
    {
      result.setResult(new BindResult(result.getMessageID(),
           ResultCode.UNWILLING_TO_PERFORM,
           "Error result by transformation", null, StaticUtils.NO_STRINGS,
           StaticUtils.NO_CONTROLS, null));
    }

    if (transformTypes.contains(TransformType.RESULT_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processCompareRequest(
                   final InMemoryInterceptedCompareRequest request)
         throws LDAPException
  {
    final ObjectPair<Set<TransformType>,Control[]> transformationData =
         getTransformTypes(request.getRequest());

    // If there are no transformation types to apply, then return without doing
    // anything.
    final Set<TransformType> transformTypes =
         transformationData.getFirst();
    if (transformTypes.isEmpty())
    {
      return;
    }


    // Store the set of transformation types in the operation state for any
    // necessary result processing.
    request.setProperty(STATE_KEY_TRANSFORM_TYPES, transformTypes);


    // Update the request to remove the transformation controls.
    final Control[] remainingControls = transformationData.getSecond();
    final CompareRequest compareRequest =
         request.getRequest().duplicate(remainingControls);


    // Apply any necessary transformations to the request.
    if (transformTypes.contains(TransformType.REJECT_REQUEST))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           "Rejected by transformation control");
    }

    if (transformTypes.contains(TransformType.REQUEST_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(TransformType.ALTER_DN))
    {
      compareRequest.setDN("ou=altered,dc=example,dc=com");
    }

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        request.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Request")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        request.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Request", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }


    // Update the add request to be processed.
    request.setRequest(compareRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processCompareResult(
                   final InMemoryInterceptedCompareResult result)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         result.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        result.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Response")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        result.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Result", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.ERROR_RESULT))
    {
      result.setResult(new LDAPResult(result.getMessageID(),
           ResultCode.UNWILLING_TO_PERFORM,
           "Error result by transformation", null, StaticUtils.NO_STRINGS,
           StaticUtils.NO_CONTROLS));
    }

    if (transformTypes.contains(TransformType.RESULT_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processDeleteRequest(
                   final InMemoryInterceptedDeleteRequest request)
         throws LDAPException
  {
    final ObjectPair<Set<TransformType>,Control[]> transformationData =
         getTransformTypes(request.getRequest());

    // If there are no transformation types to apply, then return without doing
    // anything.
    final Set<TransformType> transformTypes =
         transformationData.getFirst();
    if (transformTypes.isEmpty())
    {
      return;
    }


    // Store the set of transformation types in the operation state for any
    // necessary result processing.
    request.setProperty(STATE_KEY_TRANSFORM_TYPES, transformTypes);


    // Update the request to remove the transformation controls.
    final Control[] remainingControls = transformationData.getSecond();
    final DeleteRequest deleteRequest =
         request.getRequest().duplicate(remainingControls);


    // Apply any necessary transformations to the request.
    if (transformTypes.contains(TransformType.REJECT_REQUEST))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           "Rejected by transformation control");
    }

    if (transformTypes.contains(TransformType.REQUEST_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(TransformType.ALTER_DN))
    {
      deleteRequest.setDN("ou=altered,dc=example,dc=com");
    }

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        request.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Request")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        request.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Request", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }


    // Update the add request to be processed.
    request.setRequest(deleteRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processDeleteResult(final InMemoryInterceptedDeleteResult result)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         result.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        result.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Response")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        result.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Result", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.ERROR_RESULT))
    {
      result.setResult(new LDAPResult(result.getMessageID(),
           ResultCode.UNWILLING_TO_PERFORM,
           "Error result by transformation", null, StaticUtils.NO_STRINGS,
           StaticUtils.NO_CONTROLS));
    }

    if (transformTypes.contains(TransformType.RESULT_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processExtendedRequest(
                   final InMemoryInterceptedExtendedRequest request)
         throws LDAPException
  {
    final ObjectPair<Set<TransformType>,Control[]> transformationData =
         getTransformTypes(request.getRequest());

    // If there are no transformation types to apply, then return without doing
    // anything.
    final Set<TransformType> transformTypes =
         transformationData.getFirst();
    if (transformTypes.isEmpty())
    {
      return;
    }


    // Store the set of transformation types in the operation state for any
    // necessary result processing.
    request.setProperty(STATE_KEY_TRANSFORM_TYPES, transformTypes);


    // Update the request to remove the transformation controls.
    final Control[] remainingControls = transformationData.getSecond();
    final ExtendedRequest extendedRequest =
         request.getRequest().duplicate(remainingControls);


    // Apply any necessary transformations to the request.
    if (transformTypes.contains(TransformType.REJECT_REQUEST))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           "Rejected by transformation control");
    }

    if (transformTypes.contains(TransformType.REQUEST_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        request.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Request")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        request.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Request", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }


    // Update the add request to be processed.
    request.setRequest(extendedRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processExtendedResult(
                   final InMemoryInterceptedExtendedResult result)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         result.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        result.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Response")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        result.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Result", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.ERROR_RESULT))
    {
      result.setResult(new ExtendedResult(result.getMessageID(),
           ResultCode.UNWILLING_TO_PERFORM,
           "Error result by transformation", null, StaticUtils.NO_STRINGS,
           null, null, StaticUtils.NO_CONTROLS));
    }

    if (transformTypes.contains(TransformType.RESULT_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processModifyRequest(
                   final InMemoryInterceptedModifyRequest request)
         throws LDAPException
  {
    final ObjectPair<Set<TransformType>,Control[]> transformationData =
         getTransformTypes(request.getRequest());

    // If there are no transformation types to apply, then return without doing
    // anything.
    final Set<TransformType> transformTypes =
         transformationData.getFirst();
    if (transformTypes.isEmpty())
    {
      return;
    }


    // Store the set of transformation types in the operation state for any
    // necessary result processing.
    request.setProperty(STATE_KEY_TRANSFORM_TYPES, transformTypes);


    // Update the request to remove the transformation controls.
    final Control[] remainingControls = transformationData.getSecond();
    final ModifyRequest modifyRequest =
         request.getRequest().duplicate(remainingControls);


    // Apply any necessary transformations to the request.
    if (transformTypes.contains(TransformType.REJECT_REQUEST))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           "Rejected by transformation control");
    }

    if (transformTypes.contains(TransformType.REQUEST_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(TransformType.ALTER_DN))
    {
      modifyRequest.setDN("ou=altered,dc=example,dc=com");
    }

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        request.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Request")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        request.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Request", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }


    // Update the add request to be processed.
    request.setRequest(modifyRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processModifyResult(final InMemoryInterceptedModifyResult result)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         result.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        result.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Response")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        result.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Result", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.ERROR_RESULT))
    {
      result.setResult(new LDAPResult(result.getMessageID(),
           ResultCode.UNWILLING_TO_PERFORM,
           "Error result by transformation", null, StaticUtils.NO_STRINGS,
           StaticUtils.NO_CONTROLS));
    }

    if (transformTypes.contains(TransformType.RESULT_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processModifyDNRequest(
                   final InMemoryInterceptedModifyDNRequest request)
         throws LDAPException
  {
    final ObjectPair<Set<TransformType>,Control[]> transformationData =
         getTransformTypes(request.getRequest());

    // If there are no transformation types to apply, then return without doing
    // anything.
    final Set<TransformType> transformTypes =
         transformationData.getFirst();
    if (transformTypes.isEmpty())
    {
      return;
    }


    // Store the set of transformation types in the operation state for any
    // necessary result processing.
    request.setProperty(STATE_KEY_TRANSFORM_TYPES, transformTypes);


    // Update the request to remove the transformation controls.
    final Control[] remainingControls = transformationData.getSecond();
    final ModifyDNRequest modifyDNRequest =
         request.getRequest().duplicate(remainingControls);


    // Apply any necessary transformations to the request.
    if (transformTypes.contains(TransformType.REJECT_REQUEST))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           "Rejected by transformation control");
    }

    if (transformTypes.contains(TransformType.REQUEST_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(TransformType.ALTER_DN))
    {
      modifyDNRequest.setDN("ou=altered,dc=example,dc=com");
    }

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        request.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Request")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        request.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Request", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }


    // Update the add request to be processed.
    request.setRequest(modifyDNRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processModifyDNResult(
                   final InMemoryInterceptedModifyDNResult result)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         result.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        result.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Response")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        result.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Result", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.ERROR_RESULT))
    {
      result.setResult(new LDAPResult(result.getMessageID(),
           ResultCode.UNWILLING_TO_PERFORM,
           "Error result by transformation", null, StaticUtils.NO_STRINGS,
           StaticUtils.NO_CONTROLS));
    }

    if (transformTypes.contains(TransformType.RESULT_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processSearchRequest(
                   final InMemoryInterceptedSearchRequest request)
         throws LDAPException
  {
    final ObjectPair<Set<TransformType>,Control[]> transformationData =
         getTransformTypes(request.getRequest());

    // If there are no transformation types to apply, then return without doing
    // anything.
    final Set<TransformType> transformTypes =
         transformationData.getFirst();
    if (transformTypes.isEmpty())
    {
      return;
    }


    // Store the set of transformation types in the operation state for any
    // necessary result processing.
    request.setProperty(STATE_KEY_TRANSFORM_TYPES, transformTypes);


    // Update the request to remove the transformation controls.
    final Control[] remainingControls = transformationData.getSecond();
    final SearchRequest searchRequest =
         request.getRequest().duplicate(remainingControls);


    // Apply any necessary transformations to the request.
    if (transformTypes.contains(TransformType.REJECT_REQUEST))
    {
      throw new LDAPException(ResultCode.UNWILLING_TO_PERFORM,
           "Rejected by transformation control");
    }

    if (transformTypes.contains(TransformType.REQUEST_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(TransformType.ALTER_DN))
    {
      searchRequest.setBaseDN("ou=altered,dc=example,dc=com");
    }

    if (transformTypes.contains(TransformType.INJECT_ENTRY))
    {
      try
      {
        request.sendSearchEntry(new Entry(
             "dn: ou=Request,ou=injected,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: Request"));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.INJECT_REFERENCE))
    {
      try
      {
        final String[] referralURLs =
        {
          "ldap://" + request.getConnectedAddress() + ':' +
               request.getConnectedPort() +
               "/ou=Request,ou=injected,dc=example,dc=com"
        };

        request.sendSearchReference(
             new SearchResultReference(referralURLs, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        request.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Request")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        request.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Request", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }


    // Update the add request to be processed.
    request.setRequest(searchRequest);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processSearchEntry(final InMemoryInterceptedSearchEntry entry)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         entry.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(TransformType.SUPPRESS_ENTRY))
    {
      entry.setSearchEntry(null);
      return;
    }

    if (transformTypes.contains(TransformType.ENTRY_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(TransformType.ALTER_ENTRY))
    {
      final Entry e = entry.getSearchEntry().duplicate();
      e.setDN("ou=altered,dc=example,dc=com");
      entry.setSearchEntry(e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processSearchReference(
                   final InMemoryInterceptedSearchReference reference)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         reference.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(TransformType.SUPPRESS_REFERENCE))
    {
      reference.setSearchReference(null);
      return;
    }

    if (transformTypes.contains(TransformType.REFERENCE_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(TransformType.ALTER_REFERENCE))
    {
      final SearchResultReference r = reference.getSearchReference();
      final String[] newURLs = new String[r.getReferralURLs().length];
      System.arraycopy(r.getReferralURLs(), 0, newURLs, 0, newURLs.length);

      for (int i=0; i < newURLs.length; i++)
      {
        try
        {
          final LDAPURL url = new LDAPURL(newURLs[i]);
          newURLs[i] = new LDAPURL(url.getScheme(), url.getHost(),
               url.getPort(), new DN("ou=altered,dc=example,dc=com"),
               url.getAttributes(), url.getScope(), url.getFilter()).toString();
        } catch (final Exception e) {}
      }

      reference.setSearchReference(new SearchResultReference(newURLs,
           r.getControls()));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processSearchResult(final InMemoryInterceptedSearchResult result)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         result.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(TransformType.INJECT_ENTRY))
    {
      try
      {
        result.sendSearchEntry(new Entry(
             "dn: ou=Result,ou=injected,dc=example,dc=com",
             "objectClass: top",
             "objectClass: organizationalUnit",
             "ou: Result"));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.INJECT_REFERENCE))
    {
      try
      {
        final String[] referralURLs =
        {
          "ldap://" + result.getConnectedAddress() + ':' +
               result.getConnectedPort() +
               "/ou=Result,ou=injected,dc=example,dc=com"
        };

        result.sendSearchReference(
             new SearchResultReference(referralURLs, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_INTERMEDIATE_RESPONSE))
    {
      try
      {
        result.sendIntermediateResponse(new IntermediateResponse(
             INTERMEDIATE_RESPONSE_OID,
             new ASN1OctetString("Injected in Response")));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(
         TransformType.INJECT_UNSOLICITED_NOTIFICATION))
    {
      try
      {
        result.sendUnsolicitedNotification(new ExtendedResult(
             0, ResultCode.SUCCESS, "Injected by Result", null, null,
             UNSOLICITED_NOTIFICATION_OID, null, null));
      } catch (final Exception e) {}
    }

    if (transformTypes.contains(TransformType.ERROR_RESULT))
    {
      result.setResult(new LDAPResult(result.getMessageID(),
           ResultCode.UNWILLING_TO_PERFORM,
           "Error result by transformation", null, StaticUtils.NO_STRINGS,
           StaticUtils.NO_CONTROLS));
    }

    if (transformTypes.contains(TransformType.RESULT_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void processIntermediateResponse(
                   final InMemoryInterceptedIntermediateResponse response)
  {
    // See if there are any transformations that should be applied.
    final Object transformTypesObj =
         response.getProperty(STATE_KEY_TRANSFORM_TYPES);
    if (transformTypesObj == null)
    {
      return;
    }

    @SuppressWarnings("unchecked")
    final Set<TransformType> transformTypes =
         (Set<TransformType>) transformTypesObj;

    if (transformTypes.contains(
         TransformType.SUPPRESS_INTERMEDIATE_RESPONSE))
    {
      response.setIntermediateResponse(null);
      return;
    }

    if (transformTypes.contains(TransformType.
         INTERMEDIATE_RESPONSE_RUNTIME_EXCEPTION))
    {
      throw new RuntimeException();
    }

    if (transformTypes.contains(
         TransformType.ALTER_INTERMEDIATE_RESPONSE))
    {
      response.setIntermediateResponse(new IntermediateResponse(
           INTERMEDIATE_RESPONSE_OID,
           new ASN1OctetString("Altered Value"),
           response.getIntermediateResponse().getControls()));
    }
  }



  /**
   * Examines the controls included in the provided request to determine the
   * types of transformations that should be applied during processing.
   *
   * @param  request  The request to examine.
   *
   * @return  An object that combines the set of transformations that should be
   *          applied and the remaining controls that remain to be processed by
   *          the operation.
   */
  private static ObjectPair<Set<TransformType>,Control[]>
                      getTransformTypes(final ReadOnlyLDAPRequest request)
  {
    final EnumSet<TransformType> transformTypes =
         EnumSet.noneOf(TransformType.class);
    final ArrayList<Control> remainingControls =
         new ArrayList<Control>(request.getControlList());

    final Iterator<Control> controlIterator = remainingControls.iterator();
    while (controlIterator.hasNext())
    {
      final Control c = controlIterator.next();
      if (c.getOID().equals(TRANSFORM_CONTROL_OID))
      {
        try
        {
          transformTypes.add(
               TransformType.valueOf(c.getValue().stringValue()));
        } catch (final Exception e) {}

        controlIterator.remove();
      }
    }

    final Control[] controlArray = new Control[remainingControls.size()];
    remainingControls.toArray(controlArray);

    return new ObjectPair<Set<TransformType>,Control[]>(
         transformTypes, controlArray);
  }



  /**
   * Creates an array of request controls for the specified transformation
   * types.
   *
   * @param  transformTypes  The set of transformation types for which to
   *                              generate request controls.
   *
   * @return  The array of generated controls.
   */
  public static Control[] createControls(
                               final TransformType... transformTypes)
  {
    if ((transformTypes == null) || (transformTypes.length == 0))
    {
      return StaticUtils.NO_CONTROLS;
    }

    final Control[] controls = new Control[transformTypes.length];
    for (int i=0; i < transformTypes.length; i++)
    {
      controls[i] = new Control(TRANSFORM_CONTROL_OID, true,
           new ASN1OctetString(transformTypes[i].name()));
    }

    return controls;
  }
}
