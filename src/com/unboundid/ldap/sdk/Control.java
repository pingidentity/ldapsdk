/*
 * Copyright 2007-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2023 Ping Identity Corporation
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
 * Copyright (C) 2007-2023 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Buffer;
import com.unboundid.asn1.ASN1BufferSequence;
import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1StreamReader;
import com.unboundid.asn1.ASN1StreamReaderSequence;
import com.unboundid.ldap.sdk.controls.AssertionRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityResponseControl;
import com.unboundid.ldap.sdk.controls.DraftLDUPSubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.MatchedValuesRequestControl;
import com.unboundid.ldap.sdk.controls.PasswordExpiredControl;
import com.unboundid.ldap.sdk.controls.PasswordExpiringControl;
import com.unboundid.ldap.sdk.controls.PermissiveModifyRequestControl;
import com.unboundid.ldap.sdk.controls.PostReadRequestControl;
import com.unboundid.ldap.sdk.controls.PostReadResponseControl;
import com.unboundid.ldap.sdk.controls.PreReadRequestControl;
import com.unboundid.ldap.sdk.controls.PreReadResponseControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV1RequestControl;
import com.unboundid.ldap.sdk.controls.ProxiedAuthorizationV2RequestControl;
import com.unboundid.ldap.sdk.controls.ServerSideSortRequestControl;
import com.unboundid.ldap.sdk.controls.ServerSideSortResponseControl;
import com.unboundid.ldap.sdk.controls.SimplePagedResultsControl;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.controls.VirtualListViewRequestControl;
import com.unboundid.ldap.sdk.controls.VirtualListViewResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.AccountUsableRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.AccountUsableResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AdministrativeOperationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.ExcludeBranchRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            ExtendedSchemaInfoRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GenerateAccessTokenRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GenerateAccessTokenResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GeneratePasswordRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GeneratePasswordResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetAuthorizationEntryRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetAuthorizationEntryResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetBackendSetIDRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetBackendSetIDResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetEffectiveRightsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetPasswordPolicyStateIssuesRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetPasswordPolicyStateIssuesResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetRecentLoginHistoryRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetRecentLoginHistoryResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.GetServerIDRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.GetServerIDResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetUserResourceLimitsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetUserResourceLimitsResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.HardDeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IgnoreNoUserModificationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IntermediateClientRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            IntermediateClientResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.JSONFormattedRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.JSONFormattedResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.JoinResultControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            MatchingEntryCountRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            MatchingEntryCountResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            NameWithEntryUUIDRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.NoOpRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OverrideSearchLimitsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.PasswordPolicyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordPolicyResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordUpdateBehaviorRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordValidationDetailsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordValidationDetailsResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PermitUnindexedSearchRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.PurgePasswordRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            RealAttributesOnlyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            RejectUnindexedSearchRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            ReplicationRepairRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.RetainIdentityRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.RetirePasswordRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            ReturnConflictEntriesRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            RouteToBackendSetRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.RouteToServerRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.SoftDeleteResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SoftDeletedEntryAccessRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.SoftDeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SuppressOperationalAttributeUpdateRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            SuppressReferentialIntegrityUpdatesRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.UndeleteRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.UniquenessRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.UniquenessResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            UnsolicitedCancelResponseControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            VirtualAttributesOnlyRequestControl;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure that represents an LDAP control.  A
 * control is an element that may be attached to an LDAP request or response
 * to provide additional information about the processing that should be (or has
 * been) performed.  This class may be overridden to provide additional
 * processing for specific types of controls.
 * <BR><BR>
 * A control includes the following elements:
 * <UL>
 *   <LI>An object identifier (OID), which identifies the type of control.</LI>
 *   <LI>A criticality flag, which indicates whether the control should be
 *       considered critical to the processing of the operation.  If a control
 *       is marked critical but the server either does not support that control
 *       or it is not appropriate for the associated request, then the server
 *       will reject the request.  If a control is not marked critical and the
 *       server either does not support it or it is not appropriate for the
 *       associated request, then the server will simply ignore that
 *       control and process the request as if it were not present.</LI>
 *   <LI>An optional value, which provides additional information for the
 *       control.  Some controls do not take values, and the value encoding for
 *       controls which do take values varies based on the type of control.</LI>
 * </UL>
 * Controls may be included in a request from the client to the server, as well
 * as responses from the server to the client (including intermediate response,
 * search result entry, and search result references, in addition to the final
 * response message for an operation).  When using request controls, they may be
 * included in the request object at the time it is created, or may be added
 * after the fact for {@link UpdatableLDAPRequest} objects.  When using
 * response controls, each response control class includes a {@code get} method
 * that can be used to extract the appropriate control from an appropriate
 * result (e.g.,  {@link LDAPResult}, {@link SearchResultEntry}, or
 * {@link SearchResultReference}).
 */
@Extensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class Control
       implements Serializable
{
  /**
   * The BER type to use for the encoded set of controls in an LDAP message.
   */
  private static final byte CONTROLS_TYPE = (byte) 0xA0;



  /**
   * A map of the decodable control classes that have been registered with the
   * LDAP SDK, mapped from OID to fully-qualified class name.
   */
  @NotNull static final ConcurrentHashMap<String,String>
       DECODEABLE_CONTROL_CLASS_NAMES = new ConcurrentHashMap<>();



  /**
   * A map of the instantiated decodeable control classes registered with the
   * LDAP SDK, mapped from OID to class instance.
   */
  @NotNull private static final ConcurrentHashMap<String,DecodeableControl>
       DECODEABLE_CONTROL_INSTANCES = new ConcurrentHashMap<>();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4440956109070220054L;



  // The encoded value for this control, if there is one.
  @Nullable private final ASN1OctetString value;

  // Indicates whether this control should be considered critical.
  private final boolean isCritical;

  // The OID for this control
  @NotNull private final String oid;



  static
  {
    com.unboundid.ldap.sdk.controls.ControlHelper.
         registerDefaultResponseControls();
    com.unboundid.ldap.sdk.experimental.ControlHelper.
         registerDefaultResponseControls();
    com.unboundid.ldap.sdk.unboundidds.controls.ControlHelper.
         registerDefaultResponseControls();
  }



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.  All
   * {@code DecodeableControl} objects must provide a default constructor that
   * can be used to create an instance suitable for invoking the
   * {@code decodeControl} method.
   */
  protected Control()
  {
    oid        = null;
    isCritical = true;
    value      = null;
  }



  /**
   * Creates a new control whose fields are initialized from the contents of the
   * provided control.
   *
   * @param  control  The control whose information should be used to create
   *                  this new control.
   */
  protected Control(@NotNull final Control control)
  {
    oid        = control.oid;
    isCritical = control.isCritical;
    value      = control.value;
  }



  /**
   * Creates a new control with the provided OID.  It will not be critical, and
   * it will not have a value.
   *
   * @param  oid  The OID for this control.  It must not be {@code null}.
   */
  public Control(@NotNull final String oid)
  {
    Validator.ensureNotNull(oid);

    this.oid   = oid;
    isCritical = false;
    value      = null;
  }



  /**
   * Creates a new control with the provided OID and criticality.  It will not
   * have a value.
   *
   * @param  oid         The OID for this control.  It must not be {@code null}.
   * @param  isCritical  Indicates whether this control should be considered
   *                     critical.
   */
  public Control(@NotNull final String oid, final boolean isCritical)
  {
    Validator.ensureNotNull(oid);

    this.oid        = oid;
    this.isCritical = isCritical;
    value           = null;
  }



  /**
   * Creates a new control with the provided information.
   *
   * @param  oid         The OID for this control.  It must not be {@code null}.
   * @param  isCritical  Indicates whether this control should be considered
   *                     critical.
   * @param  value       The value for this control.  It may be {@code null} if
   *                     there is no value.
   */
  public Control(@NotNull final String oid, final boolean isCritical,
                 @Nullable final ASN1OctetString value)
  {
    Validator.ensureNotNull(oid);

    this.oid        = oid;
    this.isCritical = isCritical;
    this.value      = value;
  }



  /**
   * Retrieves the OID for this control.
   *
   * @return  The OID for this control.
   */
  @NotNull()
  public final String getOID()
  {
    return oid;
  }



  /**
   * Indicates whether this control should be considered critical.
   *
   * @return  {@code true} if this control should be considered critical, or
   *          {@code false} if not.
   */
  public final boolean isCritical()
  {
    return isCritical;
  }



  /**
   * Indicates whether this control has a value.
   *
   * @return  {@code true} if this control has a value, or {@code false} if not.
   */
  public final boolean hasValue()
  {
    return (value != null);
  }



  /**
   * Retrieves the encoded value for this control.
   *
   * @return  The encoded value for this control, or {@code null} if there is no
   *          value.
   */
  @Nullable()
  public final ASN1OctetString getValue()
  {
    return value;
  }



  /**
   * Writes an ASN.1-encoded representation of this control to the provided
   * ASN.1 stream writer.
   *
   * @param  writer  The ASN.1 stream writer to which the encoded representation
   *                 should be written.
   */
  public final void writeTo(@NotNull final ASN1Buffer writer)
  {
    final ASN1BufferSequence controlSequence = writer.beginSequence();
    writer.addOctetString(oid);

    if (isCritical)
    {
      writer.addBoolean(true);
    }

    if (value != null)
    {
      writer.addOctetString(value.getValue());
    }

    controlSequence.end();
  }



  /**
   * Encodes this control to an ASN.1 sequence suitable for use in an LDAP
   * message.
   *
   * @return  The encoded representation of this control.
   */
  @NotNull()
  public final ASN1Sequence encode()
  {
    final ArrayList<ASN1Element> elementList = new ArrayList<>(3);
    elementList.add(new ASN1OctetString(oid));

    if (isCritical)
    {
      elementList.add(new ASN1Boolean(isCritical));
    }

    if (value != null)
    {
      elementList.add(new ASN1OctetString(value.getValue()));
    }

    return new ASN1Sequence(elementList);
  }



  /**
   * Reads an LDAP control from the provided ASN.1 stream reader.
   *
   * @param  reader  The ASN.1 stream reader from which to read the control.
   *
   * @return  The decoded control.
   *
   * @throws  LDAPException  If a problem occurs while attempting to read or
   *                         parse the control.
   */
  @NotNull()
  public static Control readFrom(@NotNull final ASN1StreamReader reader)
         throws LDAPException
  {
    try
    {
      final ASN1StreamReaderSequence controlSequence = reader.beginSequence();
      final String oid = reader.readString();

      boolean isCritical = false;
      ASN1OctetString value = null;
      while (controlSequence.hasMoreElements())
      {
        final byte type = (byte) reader.peek();
        switch (type)
        {
          case ASN1Constants.UNIVERSAL_BOOLEAN_TYPE:
            isCritical = reader.readBoolean();
            break;
          case ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE:
            value = new ASN1OctetString(reader.readBytes());
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_CONTROL_INVALID_TYPE.get(StaticUtils.toHex(type)));
        }
      }

      return decode(oid, isCritical, value);
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
           ERR_CONTROL_CANNOT_DECODE.get(StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Decodes the provided ASN.1 sequence as an LDAP control.
   *
   * @param  controlSequence  The ASN.1 sequence to be decoded.
   *
   * @return  The decoded control.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided ASN.1 sequence as an LDAP control.
   */
  @NotNull()
  public static Control decode(@NotNull final ASN1Sequence controlSequence)
         throws LDAPException
  {
    final ASN1Element[] elements = controlSequence.elements();

    if ((elements.length < 1) || (elements.length > 3))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CONTROL_DECODE_INVALID_ELEMENT_COUNT.get(
                                   elements.length));
    }

    final String oid =
         ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

    boolean isCritical = false;
    ASN1OctetString value = null;
    if (elements.length == 2)
    {
      switch (elements[1].getType())
      {
        case ASN1Constants.UNIVERSAL_BOOLEAN_TYPE:
          try
          {
            isCritical =
                 ASN1Boolean.decodeAsBoolean(elements[1]).booleanValue();
          }
          catch (final ASN1Exception ae)
          {
            Debug.debugException(ae);
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_CONTROL_DECODE_CRITICALITY.get(
                      StaticUtils.getExceptionMessage(ae)),
                 ae);
          }
          break;

        case ASN1Constants.UNIVERSAL_OCTET_STRING_TYPE:
          value = ASN1OctetString.decodeAsOctetString(elements[1]);
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_CONTROL_INVALID_TYPE.get(
                    StaticUtils.toHex(elements[1].getType())));
      }
    }
    else if (elements.length == 3)
    {
      try
      {
        isCritical = ASN1Boolean.decodeAsBoolean(elements[1]).booleanValue();
      }
      catch (final ASN1Exception ae)
      {
        Debug.debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CONTROL_DECODE_CRITICALITY.get(
                  StaticUtils.getExceptionMessage(ae)),
             ae);
      }

      value = ASN1OctetString.decodeAsOctetString(elements[2]);
    }

    return decode(oid, isCritical, value);
  }



  /**
   * Attempts to create the most appropriate control instance from the provided
   * information.  If a {@link DecodeableControl} instance has been registered
   * for the specified OID, then this method will attempt to use that instance
   * to construct a control.  If that fails, or if no appropriate
   * {@code DecodeableControl} is registered, then a generic control will be
   * returned.
   *
   * @param  oid         The OID for the control.  It must not be {@code null}.
   * @param  isCritical  Indicates whether the control should be considered
   *                     critical.
   * @param  value       The value for the control.  It may be {@code null} if
   *                     there is no value.
   *
   * @return  The decoded control.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided ASN.1 sequence as an LDAP control.
   */
  @NotNull()
  public static Control decode(@NotNull final String oid,
                               final boolean isCritical,
                               @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    DecodeableControl decodeableControl = DECODEABLE_CONTROL_INSTANCES.get(oid);
    if (decodeableControl == null)
    {
      final String controlClassName = DECODEABLE_CONTROL_CLASS_NAMES.get(oid);
      if (controlClassName == null)
      {
        return new Control(oid, isCritical, value);
      }

      try
      {
        final Class<?> controlClass = Class.forName(controlClassName);
        final Constructor<?> noArgumentConstructor =
             controlClass.getDeclaredConstructor();
        noArgumentConstructor.setAccessible(true);
        decodeableControl =
             (DecodeableControl) noArgumentConstructor.newInstance();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        return new Control(oid, isCritical, value);
      }
    }

    try
    {
      return decodeableControl.decodeControl(oid, isCritical, value);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return new Control(oid, isCritical, value);
    }
  }



  /**
   * Encodes the provided set of controls to an ASN.1 sequence suitable for
   * inclusion in an LDAP message.
   *
   * @param  controls  The set of controls to be encoded.
   *
   * @return  An ASN.1 sequence containing the encoded set of controls.
   */
  @NotNull()
  public static ASN1Sequence encodeControls(@NotNull final Control[] controls)
  {
    final ASN1Sequence[] controlElements = new ASN1Sequence[controls.length];
    for (int i=0; i < controls.length; i++)
    {
      controlElements[i] = controls[i].encode();
    }

    return new ASN1Sequence(CONTROLS_TYPE, controlElements);
  }



  /**
   * Decodes the contents of the provided sequence as a set of controls.
   *
   * @param  controlSequence  The ASN.1 sequence containing the encoded set of
   *                          controls.
   *
   * @return  The decoded set of controls.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode any
   *                         of the controls.
   */
  @NotNull()
  public static Control[] decodeControls(
                               @NotNull final ASN1Sequence controlSequence)
         throws LDAPException
  {
    final ASN1Element[] controlElements = controlSequence.elements();
    final Control[] controls = new Control[controlElements.length];

    for (int i=0; i < controlElements.length; i++)
    {
      try
      {
        controls[i] = decode(ASN1Sequence.decodeAsSequence(controlElements[i]));
      }
      catch (final ASN1Exception ae)
      {
        Debug.debugException(ae);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CONTROLS_DECODE_ELEMENT_NOT_SEQUENCE.get(
                  StaticUtils.getExceptionMessage(ae)),
             ae);
      }
    }

    return controls;
  }



  /**
   * Registers the specified class to be used in an attempt to decode controls
   * with the specified OID.
   *
   * @param  oid        The response control OID for which the provided class
   *                    will be registered.
   * @param  className  The fully-qualified name for the Java class that
   *                    provides the decodeable control implementation to use
   *                    for the provided OID.
   */
  public static void registerDecodeableControl(@NotNull final String oid,
                                               @NotNull final String className)
  {
    DECODEABLE_CONTROL_CLASS_NAMES.put(oid, className);
    DECODEABLE_CONTROL_INSTANCES.remove(oid);
  }



  /**
   * Registers the provided class to be used in an attempt to decode controls
   * with the specified OID.
   *
   * @param  oid              The response control OID for which the provided
   *                          class will be registered.
   * @param  controlInstance  The control instance that should be used to decode
   *                          controls with the provided OID.
   */
  public static void registerDecodeableControl(@NotNull final String oid,
                          @NotNull final DecodeableControl controlInstance)
  {
    DECODEABLE_CONTROL_CLASS_NAMES.put(oid,
         controlInstance.getClass().getName());
    DECODEABLE_CONTROL_INSTANCES.put(oid, controlInstance);
  }



  /**
   * Deregisters the decodeable control class associated with the provided OID.
   *
   * @param  oid  The response control OID for which to deregister the
   *              decodeable control class.
   */
  public static void deregisterDecodeableControl(@NotNull final String oid)
  {
    DECODEABLE_CONTROL_CLASS_NAMES.remove(oid);
    DECODEABLE_CONTROL_INSTANCES.remove(oid);
  }



  /**
   * Retrieves a hash code for this control.
   *
   * @return  A hash code for this control.
   */
  @Override()
  public final int hashCode()
  {
    int hashCode = oid.hashCode();

    if (isCritical)
    {
      hashCode++;
    }

    if (value != null)
    {
      hashCode += value.hashCode();
    }

    return hashCode;
  }



  /**
   * Indicates whether the provided object may be considered equal to this
   * control.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object may be considered equal to
   *          this control, or {@code false} if not.
   */
  @Override()
  public final boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o == this)
    {
      return true;
    }

    if (! (o instanceof Control))
    {
      return false;
    }

    final Control c = (Control) o;
    if (! oid.equals(c.oid))
    {
      return false;
    }

    if (isCritical != c.isCritical)
    {
      return false;
    }

    if (value == null)
    {
      if (c.value != null)
      {
        return false;
      }
    }
    else
    {
      if (c.value == null)
      {
        return false;
      }

      if (! value.equals(c.value))
      {
        return false;
      }
    }


    return true;
  }



  /**
   * Retrieves the user-friendly name for this control, if available.  If no
   * user-friendly name has been defined, then the OID will be returned.
   *
   * @return  The user-friendly name for this control, or the OID if no
   *          user-friendly name is available.
   */
  @NotNull()
  public String getControlName()
  {
    // By default, we will return the OID.  Subclasses should override this to
    // provide the user-friendly name.
    return oid;
  }



  /**
   * Retrieves a representation of this control as a JSON object.  The JSON
   * object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.
   *   </LI>
   *   <LI>
   *     {@code control-name} -- An optional string field whose value is a
   *     human-readable name for this control.  This field is only intended for
   *     descriptive purposes, and when decoding a control, the {@code oid}
   *     field should be used to identify the type of control.
   *   </LI>
   *   <LI>
   *     {@code criticality} -- A mandatory Boolean field used to indicate
   *     whether this control is considered critical.
   *   </LI>
   *   <LI>
   *     {@code value-base64} -- An optional string field whose value is a
   *     base64-encoded representation of the raw value for this control.  At
   *     most one of the {@code value-base64} and {@code value-json} fields may
   *     be present, and both fields will be absent for controls that do not
   *     have a value.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly, control-specific representation of the value for this
   *     control.  This representation of the value is only available for
   *     certain types of controls, and subclasses will override this method to
   *     provide an appropriate representation of that value, and their Javadoc
   *     documentation will describe the fields that may be present in the
   *     value.  At most one of the  {@code value-base64} and {@code value-json}
   *     fields may be present, and both fields will be absent for controls that
   *     do not have a value.
   *   </LI>
   * </UL>
   *
   * @return  A JSON object that contains a representation of this control.
   */
  @NotNull()
  public JSONObject toJSONControl()
  {
    final Map<String,JSONValue> fields = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(4));

    fields.put(JSONControlDecodeHelper.JSON_FIELD_OID, new JSONString(oid));

    final String name = getControlName();
    if ((name != null) && (! name.equals(oid)))
    {
      fields.put(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
           new JSONString(name));
    }

    fields.put(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
         new JSONBoolean(isCritical));

    if (value != null)
    {
      fields.put(JSONControlDecodeHelper.JSON_FIELD_VALUE_BASE64,
           new JSONString(Base64.encode(value.getValue())));
    }

    return new JSONObject(fields);
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * control.  If the OID extracted from the provided JSON object matches the
   * OID for a control with a known-supported encoding, then control-specific
   * decoding will be used to allow for a more user-friendly version of the
   * object (for example, with a value formatted as a JSON object rather than
   * raw base64-encoded data).  If no specific support is available for the
   * specified control, then a more generic decoding will be used, and only
   * base64-encoded values will be supported.
   *
   * @param  controlObject     The JSON object to be decoded.  It must not be
   *                           {@code null}.
   * @param  strict            Indicates whether to use strict mode when
   *                           decoding the provided JSON object.  If this is
   *                           {@code true}, then this method will throw an
   *                           exception if the provided JSON object contains
   *                           any unrecognized fields, and potentially if any
   *                           other constraints are violated.  If this is
   *                           {@code false}, then unrecognized fields will be
   *                           ignored, and potentially other lenient parsing
   *                           will be used.
   * @param  isRequestControl  Indicates whether the provided JSON object
   *                           represents a request control (if {@code true})
   *                           rather than a response control
   *                           (if {@code false}).  This will be used in cases
   *                           where both a request and response control of the
   *                           same type share the same OID.
   *
   * @return  The control that was decoded from the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid control.
   */
  @NotNull()
  public static Control decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict,
              final boolean isRequestControl)
         throws LDAPException
  {
    final String oid = controlObject.getFieldAsString(
         JSONControlDecodeHelper.JSON_FIELD_OID);
    if (oid == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CONTROL_JSON_OBJECT_MISSING_OID.get(
                controlObject.toSingleLineString(),
                JSONControlDecodeHelper.JSON_FIELD_OID));
    }

    switch (oid)
    {
      // NOTE:  The account usable request and response controls use the same
      // OID.
      case AccountUsableRequestControl.ACCOUNT_USABLE_REQUEST_OID:
        if (isRequestControl)
        {
          return AccountUsableRequestControl.decodeJSONControl(
               controlObject, strict);
        }
        else
        {
          return AccountUsableResponseControl.decodeJSONControl(
               controlObject, strict);
        }

      case AdministrativeOperationRequestControl.
           ADMINISTRATIVE_OPERATION_REQUEST_OID:
        return AdministrativeOperationRequestControl.decodeJSONControl(
             controlObject, strict);

      case AssertionRequestControl.ASSERTION_REQUEST_OID:
        return AssertionRequestControl.decodeJSONControl(controlObject, strict);

      case AssuredReplicationRequestControl.ASSURED_REPLICATION_REQUEST_OID:
        return AssuredReplicationRequestControl.decodeJSONControl(
             controlObject, strict);

      case AssuredReplicationResponseControl.ASSURED_REPLICATION_RESPONSE_OID:
        return AssuredReplicationResponseControl.decodeJSONControl(
             controlObject, strict);

      case AuthorizationIdentityRequestControl.
           AUTHORIZATION_IDENTITY_REQUEST_OID:
        return AuthorizationIdentityRequestControl.decodeJSONControl(
             controlObject, strict);

      case AuthorizationIdentityResponseControl.
           AUTHORIZATION_IDENTITY_RESPONSE_OID:
        return AuthorizationIdentityResponseControl.decodeJSONControl(
             controlObject, strict);

      case DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID:
        return DraftLDUPSubentriesRequestControl.decodeJSONControl(
             controlObject, strict);

      case ExcludeBranchRequestControl.EXCLUDE_BRANCH_REQUEST_OID:
        return ExcludeBranchRequestControl.decodeJSONControl(
             controlObject, strict);

      case ExtendedSchemaInfoRequestControl.EXTENDED_SCHEMA_INFO_REQUEST_OID:
        return ExtendedSchemaInfoRequestControl.decodeJSONControl(
             controlObject, strict);

      case GenerateAccessTokenRequestControl.GENERATE_ACCESS_TOKEN_REQUEST_OID:
        return GenerateAccessTokenRequestControl.decodeJSONControl(
             controlObject, strict);

      case GenerateAccessTokenResponseControl.
           GENERATE_ACCESS_TOKEN_RESPONSE_OID:
        return GenerateAccessTokenResponseControl.decodeJSONControl(
             controlObject, strict);

      case GeneratePasswordRequestControl.GENERATE_PASSWORD_REQUEST_OID:
        return GeneratePasswordRequestControl.decodeJSONControl(
             controlObject, strict);

      case GeneratePasswordResponseControl.GENERATE_PASSWORD_RESPONSE_OID:
        return GeneratePasswordResponseControl.decodeJSONControl(
             controlObject, strict);

      // NOTE:  The get authorization entry request and response controls use
      // the same OID.
      case GetAuthorizationEntryRequestControl.
           GET_AUTHORIZATION_ENTRY_REQUEST_OID:
        if (isRequestControl)
        {
          return GetAuthorizationEntryRequestControl.decodeJSONControl(
               controlObject, strict);
        }
        else
        {
          return GetAuthorizationEntryResponseControl.decodeJSONControl(
               controlObject, strict);
        }

      case GetBackendSetIDRequestControl.GET_BACKEND_SET_ID_REQUEST_OID:
        return GetBackendSetIDRequestControl.decodeJSONControl(
             controlObject, strict);

      case GetBackendSetIDResponseControl.GET_BACKEND_SET_ID_RESPONSE_OID:
        return GetBackendSetIDResponseControl.decodeJSONControl(
             controlObject, strict);

      case GetEffectiveRightsRequestControl.GET_EFFECTIVE_RIGHTS_REQUEST_OID:
        return GetEffectiveRightsRequestControl.decodeJSONControl(
             controlObject, strict);

      case GetPasswordPolicyStateIssuesRequestControl.
           GET_PASSWORD_POLICY_STATE_ISSUES_REQUEST_OID:
        return GetPasswordPolicyStateIssuesRequestControl.decodeJSONControl(
             controlObject, strict);

      case GetPasswordPolicyStateIssuesResponseControl.
           GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID:
        return GetPasswordPolicyStateIssuesResponseControl.decodeJSONControl(
             controlObject, strict);

      case GetRecentLoginHistoryRequestControl.
           GET_RECENT_LOGIN_HISTORY_REQUEST_OID:
        return GetRecentLoginHistoryRequestControl.decodeJSONControl(
             controlObject, strict);

      case GetRecentLoginHistoryResponseControl.
           GET_RECENT_LOGIN_HISTORY_RESPONSE_OID:
        return GetRecentLoginHistoryResponseControl.decodeJSONControl(
             controlObject, strict);

      case GetServerIDRequestControl.GET_SERVER_ID_REQUEST_OID:
        return GetServerIDRequestControl.decodeJSONControl(
             controlObject, strict);

      case GetServerIDResponseControl.GET_SERVER_ID_RESPONSE_OID:
        return GetServerIDResponseControl.decodeJSONControl(
             controlObject, strict);

      case GetUserResourceLimitsRequestControl.
           GET_USER_RESOURCE_LIMITS_REQUEST_OID:
        return GetUserResourceLimitsRequestControl.decodeJSONControl(
             controlObject, strict);

      case GetUserResourceLimitsResponseControl.
           GET_USER_RESOURCE_LIMITS_RESPONSE_OID:
        return GetUserResourceLimitsResponseControl.decodeJSONControl(
             controlObject, strict);

      case HardDeleteRequestControl.HARD_DELETE_REQUEST_OID:
        return HardDeleteRequestControl.decodeJSONControl(
             controlObject, strict);

      case IgnoreNoUserModificationRequestControl.
           IGNORE_NO_USER_MODIFICATION_REQUEST_OID:
        return IgnoreNoUserModificationRequestControl.decodeJSONControl(
             controlObject, strict);

      // NOTE:  The intermediate client request and response controls use the
      // same OID.
      case IntermediateClientRequestControl.INTERMEDIATE_CLIENT_REQUEST_OID:
        if (isRequestControl)
        {
          return IntermediateClientRequestControl.decodeJSONControl(
               controlObject, strict);
        }
        else
        {
          return IntermediateClientResponseControl.decodeJSONControl(
               controlObject, strict);
        }

      // NOTE:  The join request and result controls use the same OID.
      case JoinRequestControl.JOIN_REQUEST_OID:
        if (isRequestControl)
        {
          return JoinRequestControl.decodeJSONControl(controlObject, strict);
        }
        else
        {
          return JoinResultControl.decodeJSONControl(controlObject, strict);
        }

      case JSONFormattedRequestControl.JSON_FORMATTED_REQUEST_OID:
        return JSONFormattedRequestControl.decodeJSONControl(
             controlObject, strict);

      case JSONFormattedResponseControl.JSON_FORMATTED_RESPONSE_OID:
        return JSONFormattedResponseControl.decodeJSONControl(
             controlObject, strict);

      case ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID:
        return ManageDsaITRequestControl.decodeJSONControl(
             controlObject, strict);

      case MatchedValuesRequestControl.MATCHED_VALUES_REQUEST_OID:
        return MatchedValuesRequestControl.decodeJSONControl(
             controlObject, strict);

      case MatchingEntryCountRequestControl.MATCHING_ENTRY_COUNT_REQUEST_OID:
        return MatchingEntryCountRequestControl.decodeJSONControl(
             controlObject, strict);

      case MatchingEntryCountResponseControl.MATCHING_ENTRY_COUNT_RESPONSE_OID:
        return MatchingEntryCountResponseControl.decodeJSONControl(
             controlObject, strict);

      case NameWithEntryUUIDRequestControl.NAME_WITH_ENTRY_UUID_REQUEST_OID:
        return NameWithEntryUUIDRequestControl.decodeJSONControl(
             controlObject, strict);

      case NoOpRequestControl.NO_OP_REQUEST_OID:
        return NoOpRequestControl.decodeJSONControl(controlObject, strict);

      case OperationPurposeRequestControl.OPERATION_PURPOSE_REQUEST_OID:
        return OperationPurposeRequestControl.decodeJSONControl(
             controlObject, strict);

      case OverrideSearchLimitsRequestControl.
           OVERRIDE_SEARCH_LIMITS_REQUEST_OID:
        return OverrideSearchLimitsRequestControl.decodeJSONControl(
             controlObject, strict);

      case PasswordExpiredControl.PASSWORD_EXPIRED_OID:
        return PasswordExpiredControl.decodeJSONControl(controlObject, strict);

      case PasswordExpiringControl.PASSWORD_EXPIRING_OID:
        return PasswordExpiringControl.decodeJSONControl(controlObject, strict);

      // NOTE:  The password policy request and result controls use the same
      // OID.
      case PasswordPolicyRequestControl.PASSWORD_POLICY_REQUEST_OID:
        if (isRequestControl)
        {
          return PasswordPolicyRequestControl.decodeJSONControl(
               controlObject, strict);
        }
        else
        {
          return PasswordPolicyResponseControl.decodeJSONControl(
               controlObject, strict);
        }

      case PasswordUpdateBehaviorRequestControl.
           PASSWORD_UPDATE_BEHAVIOR_REQUEST_OID:
        return PasswordUpdateBehaviorRequestControl.decodeJSONControl(
             controlObject, strict);

      case PasswordValidationDetailsRequestControl.
           PASSWORD_VALIDATION_DETAILS_REQUEST_OID:
        return PasswordValidationDetailsRequestControl.decodeJSONControl(
             controlObject, strict);

      case PasswordValidationDetailsResponseControl.
           PASSWORD_VALIDATION_DETAILS_RESPONSE_OID:
        return PasswordValidationDetailsResponseControl.decodeJSONControl(
             controlObject, strict);

      case PermissiveModifyRequestControl.PERMISSIVE_MODIFY_REQUEST_OID:
        return PermissiveModifyRequestControl.decodeJSONControl(
             controlObject, strict);

      case PermitUnindexedSearchRequestControl.
           PERMIT_UNINDEXED_SEARCH_REQUEST_OID:
        return PermitUnindexedSearchRequestControl.decodeJSONControl(
             controlObject, strict);

      // NOTE:  The post-read request and result controls use the same OID.
      case PostReadRequestControl.POST_READ_REQUEST_OID:
        if (isRequestControl)
        {
          return PostReadRequestControl.decodeJSONControl(
               controlObject, strict);
        }
        else
        {
          return PostReadResponseControl.decodeJSONControl(
               controlObject, strict);
        }

      // NOTE:  The pre-read request and result controls use the same OID.
      case PreReadRequestControl.PRE_READ_REQUEST_OID:
        if (isRequestControl)
        {
          return PreReadRequestControl.decodeJSONControl(
               controlObject, strict);
        }
        else
        {
          return PreReadResponseControl.decodeJSONControl(
               controlObject, strict);
        }

      case ProxiedAuthorizationV1RequestControl.
           PROXIED_AUTHORIZATION_V1_REQUEST_OID:
        return ProxiedAuthorizationV1RequestControl.decodeJSONControl(
             controlObject, strict);

      case ProxiedAuthorizationV2RequestControl.
           PROXIED_AUTHORIZATION_V2_REQUEST_OID:
        return ProxiedAuthorizationV2RequestControl.decodeJSONControl(
             controlObject, strict);

      case PurgePasswordRequestControl.PURGE_PASSWORD_REQUEST_OID:
        return PurgePasswordRequestControl.decodeJSONControl(
             controlObject, strict);

      case RealAttributesOnlyRequestControl.REAL_ATTRIBUTES_ONLY_REQUEST_OID:
        return RealAttributesOnlyRequestControl.decodeJSONControl(
             controlObject, strict);

      case RejectUnindexedSearchRequestControl.
           REJECT_UNINDEXED_SEARCH_REQUEST_OID:
        return RejectUnindexedSearchRequestControl.decodeJSONControl(
             controlObject, strict);

      case ReplicationRepairRequestControl.REPLICATION_REPAIR_REQUEST_OID:
        return ReplicationRepairRequestControl.decodeJSONControl(
             controlObject, strict);

      case RetainIdentityRequestControl.RETAIN_IDENTITY_REQUEST_OID:
        return RetainIdentityRequestControl.decodeJSONControl(
             controlObject, strict);

      case RetirePasswordRequestControl.RETIRE_PASSWORD_REQUEST_OID:
        return RetirePasswordRequestControl.decodeJSONControl(
             controlObject, strict);

      case ReturnConflictEntriesRequestControl.
           RETURN_CONFLICT_ENTRIES_REQUEST_OID:
        return ReturnConflictEntriesRequestControl.decodeJSONControl(
             controlObject, strict);

      case RouteToBackendSetRequestControl.ROUTE_TO_BACKEND_SET_REQUEST_OID:
        return RouteToBackendSetRequestControl.decodeJSONControl(
             controlObject, strict);

      case RouteToServerRequestControl.ROUTE_TO_SERVER_REQUEST_OID:
        return RouteToServerRequestControl.decodeJSONControl(
             controlObject, strict);

      case ServerSideSortRequestControl.SERVER_SIDE_SORT_REQUEST_OID:
        return ServerSideSortRequestControl.decodeJSONControl(
             controlObject, strict);

      case ServerSideSortResponseControl.SERVER_SIDE_SORT_RESPONSE_OID:
        return ServerSideSortResponseControl.decodeJSONControl(
             controlObject, strict);

      case SimplePagedResultsControl.PAGED_RESULTS_OID:
        return SimplePagedResultsControl.decodeJSONControl(
             controlObject, strict);

      case SoftDeletedEntryAccessRequestControl.
           SOFT_DELETED_ENTRY_ACCESS_REQUEST_OID:
        return SoftDeletedEntryAccessRequestControl.decodeJSONControl(
             controlObject, strict);

      case SoftDeleteRequestControl.SOFT_DELETE_REQUEST_OID:
        return SoftDeleteRequestControl.decodeJSONControl(
             controlObject, strict);

      case SoftDeleteResponseControl.SOFT_DELETE_RESPONSE_OID:
        return SoftDeleteResponseControl.decodeJSONControl(
             controlObject, strict);

      case SubtreeDeleteRequestControl.SUBTREE_DELETE_REQUEST_OID:
        return SubtreeDeleteRequestControl.decodeJSONControl(
             controlObject, strict);

      case SuppressOperationalAttributeUpdateRequestControl.
           SUPPRESS_OP_ATTR_UPDATE_REQUEST_OID:
        return SuppressOperationalAttributeUpdateRequestControl.
             decodeJSONControl(controlObject, strict);

      case SuppressReferentialIntegrityUpdatesRequestControl.
           SUPPRESS_REFINT_REQUEST_OID:
        return SuppressReferentialIntegrityUpdatesRequestControl.
             decodeJSONControl(controlObject, strict);

      case UndeleteRequestControl.UNDELETE_REQUEST_OID:
        return UndeleteRequestControl.decodeJSONControl(controlObject, strict);

      case UniquenessRequestControl.UNIQUENESS_REQUEST_OID:
        return UniquenessRequestControl.decodeJSONControl(
             controlObject, strict);

      case UniquenessResponseControl.UNIQUENESS_RESPONSE_OID:
        return UniquenessResponseControl.decodeJSONControl(
             controlObject, strict);

      case UnsolicitedCancelResponseControl.UNSOLICITED_CANCEL_RESPONSE_OID:
        return UnsolicitedCancelResponseControl.decodeJSONControl(
             controlObject, strict);

      case VirtualAttributesOnlyRequestControl.
           VIRTUAL_ATTRIBUTES_ONLY_REQUEST_OID:
        return VirtualAttributesOnlyRequestControl.decodeJSONControl(
             controlObject, strict);

      case VirtualListViewRequestControl.VIRTUAL_LIST_VIEW_REQUEST_OID:
        return VirtualListViewRequestControl.decodeJSONControl(
             controlObject, strict);

      case VirtualListViewResponseControl.VIRTUAL_LIST_VIEW_RESPONSE_OID:
        return VirtualListViewResponseControl.decodeJSONControl(
             controlObject, strict);

      default:
        // The OID doesn't match that of a control for which we provide specific
        // JSON support.  Treat it as a generic control.  Note that we can't
        // support the JSON representation of the control value.
        final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
             controlObject, strict, true, false);
        if (jsonControl.getValueObject() != null)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_CONTROL_JSON_UNABLE_TO_SUPPORT_VALUE_JSON.get(
                    controlObject.toSingleLineString(),
                    JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON, oid,
                    JSONControlDecodeHelper.JSON_FIELD_VALUE_BASE64));
        }
        else
        {
          return new Control(jsonControl.getOID(), jsonControl.getCriticality(),
               jsonControl.getRawValue());
        }
    }
  }



  /**
   * Retrieves a string representation of this LDAP control.
   *
   * @return  A string representation of this LDAP control.
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
   * Appends a string representation of this LDAP control to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which to append the string representation of
   *                 this buffer.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("Control(oid=");
    buffer.append(oid);
    buffer.append(", isCritical=");
    buffer.append(isCritical);
    buffer.append(", value=");

    if (value == null)
    {
      buffer.append("{null}");
    }
    else
    {
      buffer.append("{byte[");
      buffer.append(value.getValue().length);
      buffer.append("]}");
    }

    buffer.append(')');
  }
}
