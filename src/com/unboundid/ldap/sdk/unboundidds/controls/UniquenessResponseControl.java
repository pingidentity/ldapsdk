/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
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
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a response control that may be included in the response
 * to add, modify, and modify DN requests that included the
 * {@link UniquenessRequestControl}.  It provides information about the
 * uniqueness processing that was performed.
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
 * The control has an OID of 1.3.6.1.4.1.30221.2.5.53 and a criticality of
 * false.  It must have a value with the following encoding:
 * <PRE>
 *   UniquenessResponseValue ::= SEQUENCE {
 *     uniquenessID                [0] OCTET STRING,
 *     preCommitValidationPassed   [1] BOOLEAN OPTIONAL,
 *     postCommitValidationPassed  [2] BOOLEAN OPTIONAL,
 *     validationMessage           [3] OCTET STRING OPTIONAL,
 *     ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class UniquenessResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.53) for the uniqueness response control.
   */
  @NotNull public static final String UNIQUENESS_RESPONSE_OID =
       "1.3.6.1.4.1.30221.2.5.53";



  /**
   * The BER type for the uniqueness ID element in the value sequence.
   */
  private static final byte TYPE_UNIQUENESS_ID = (byte) 0x80;



  /**
   * The BER type for the pre-commit validation passed element in the value
   * sequence.
   */
  private static final byte TYPE_PRE_COMMIT_VALIDATION_PASSED = (byte) 0x81;



  /**
   * The BER type for the post-commit validation passed element in the value
   * sequence.
   */
  private static final byte TYPE_POST_COMMIT_VALIDATION_PASSED = (byte) 0x82;



  /**
   * The BER type for the validation message element in the value sequence.
   */
  private static final byte TYPE_VALIDATION_MESSAGE = (byte) 0x83;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5090348902351420617L;



  // Indicates whether post-commit validation passed.
  @Nullable private final Boolean postCommitValidationPassed;

  // Indicates whether pre-commit validation passed.
  @Nullable private final Boolean preCommitValidationPassed;

  // A value that will be used to correlate this response control with its
  // corresponding request control.
  @NotNull private final String uniquenessID;

  // The validation message, if any.
  @Nullable private final String validationMessage;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  UniquenessResponseControl()
  {
    uniquenessID = null;
    preCommitValidationPassed = null;
    postCommitValidationPassed = null;
    validationMessage = null;
  }



  /**
   * Creates a new uniqueness response control with the provided information.
   *
   * @param  uniquenessID                The uniqueness ID that may be used to
   *                                     correlate this uniqueness response
   *                                     control with the corresponding request
   *                                     control.  This must not be
   *                                     {@code null}.
   * @param  preCommitValidationPassed   Indicates whether the pre-commit
   *                                     validation was successful.  This may be
   *                                     {@code null} if no pre-commit
   *                                     validation was attempted.
   * @param  postCommitValidationPassed  Indicates whether the post-commit
   *                                     validation was successful.  This may be
   *                                     {@code null} if no post-commit
   *                                     validation was attempted.
   * @param  validationMessage           A message with additional information
   *                                     about the validation processing.  This
   *                                     may be {@code null} if no validation
   *                                     message is needed.
   */
  public UniquenessResponseControl(@NotNull final String uniquenessID,
              @Nullable final Boolean preCommitValidationPassed,
              @Nullable final Boolean postCommitValidationPassed,
              @Nullable final String validationMessage)
  {
    super(UNIQUENESS_RESPONSE_OID, false,
         encodeValue(uniquenessID, preCommitValidationPassed,
              postCommitValidationPassed, validationMessage));

    Validator.ensureNotNull(uniquenessID);

    this.uniquenessID = uniquenessID;
    this.preCommitValidationPassed = preCommitValidationPassed;
    this.postCommitValidationPassed = postCommitValidationPassed;
    this.validationMessage = validationMessage;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this control.
   *
   * @param  uniquenessID                The uniqueness ID that may be used to
   *                                     correlate this uniqueness response
   *                                     control with the corresponding request
   *                                     control.  This must not be
   *                                     {@code null}.
   * @param  preCommitValidationPassed   Indicates whether the pre-commit
   *                                     validation was successful.  This may be
   *                                     {@code null} if no pre-commit
   *                                     validation was attempted.
   * @param  postCommitValidationPassed  Indicates whether the post-commit
   *                                     validation was successful.  This may be
   *                                     {@code null} if no post-commit
   *                                     validation was attempted.
   * @param  validationMessage           A message with additional information
   *                                     about the validation processing.  This
   *                                     may be {@code null} if no validation
   *                                     message is needed.
   *
   * @return  The encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @NotNull final String uniquenessID,
               @Nullable final Boolean preCommitValidationPassed,
               @Nullable final Boolean postCommitValidationPassed,
               @Nullable final String validationMessage)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(4);
    elements.add(new ASN1OctetString(TYPE_UNIQUENESS_ID, uniquenessID));

    if (preCommitValidationPassed != null)
    {
      elements.add(new ASN1Boolean(TYPE_PRE_COMMIT_VALIDATION_PASSED,
           preCommitValidationPassed));
    }

    if (postCommitValidationPassed != null)
    {
      elements.add(new ASN1Boolean(TYPE_POST_COMMIT_VALIDATION_PASSED,
           postCommitValidationPassed));
    }

    if (validationMessage != null)
    {
      elements.add(new ASN1OctetString(TYPE_VALIDATION_MESSAGE,
           validationMessage));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Creates a new uniqueness response control with the provided information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         uniqueness response control.
   */
  public UniquenessResponseControl(@NotNull final String oid,
                                   final boolean isCritical,
                                   @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_UNIQUENESS_RES_DECODE_NO_VALUE.get());
    }

    try
    {
      String id = null;
      Boolean prePassed = null;
      Boolean postPassed = null;
      String message = null;
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(value.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_UNIQUENESS_ID:
            id = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_PRE_COMMIT_VALIDATION_PASSED:
            prePassed = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_POST_COMMIT_VALIDATION_PASSED:
            postPassed = ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_VALIDATION_MESSAGE:
            message = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_UNIQUENESS_RES_DECODE_UNKNOWN_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }

      if (id == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_UNIQUENESS_RES_DECODE_NO_UNIQUENESS_ID.get());
      }

      uniquenessID = id;
      preCommitValidationPassed = prePassed;
      postCommitValidationPassed = postPassed;
      validationMessage = message;
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
           ERR_UNIQUENESS_RES_DECODE_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public UniquenessResponseControl decodeControl(@NotNull final String oid,
              final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new UniquenessResponseControl(oid, isCritical, value);
  }



  /**
   * Retrieves the set of uniqueness response controls included in the provided
   * result.
   *
   * @param  result  The result to process.
   *
   * @return  The set of uniqueness response controls included in the provided
   *          result, indexed by uniqueness ID.  It may be empty if the result
   *          does not include any uniqueness response controls.
   *
   * @throws  LDAPException  If a problem is encountered while getting the set
   *                         of uniqueness response controls contained in the
   *                         provided result.
   */
  @NotNull()
  public static Map<String,UniquenessResponseControl> get(
                     @NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control[] responseControls = result.getResponseControls();
    if (responseControls.length == 0)
    {
      return Collections.emptyMap();
    }

    final LinkedHashMap<String,UniquenessResponseControl> controlMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(
              responseControls.length));
    for (final Control c : responseControls)
    {
      if (! c.getOID().equals(UNIQUENESS_RESPONSE_OID))
      {
        continue;
      }

      final UniquenessResponseControl urc;
      if (c instanceof UniquenessResponseControl)
      {
        urc = (UniquenessResponseControl) c;
      }
      else
      {
        urc = new UniquenessResponseControl().decodeControl(c.getOID(),
             c.isCritical(), c.getValue());
      }

      final String uniquenessID = urc.getUniquenessID();
      if (controlMap.containsKey(uniquenessID))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_UNIQUENESS_RES_GET_ID_CONFLICT.get(uniquenessID));
      }
      else
      {
        controlMap.put(uniquenessID, urc);
      }
    }

    return Collections.unmodifiableMap(controlMap);
  }



  /**
   * Indicates whether a uniqueness conflict was found during processing.
   *
   * @return  {@code true} if a uniqueness conflict was found during processing,
   *          or {@code false} if no conflict was found or if no validation was
   *          attempted.
   */
  public boolean uniquenessConflictFound()
  {
    return ((preCommitValidationPassed == Boolean.FALSE) ||
         (postCommitValidationPassed == Boolean.FALSE));
  }



  /**
   * Retrieves the identifier that may be used to correlate this uniqueness
   * response control with the corresponding request control.  This is primarily
   * useful for requests that contain multiple uniqueness controls, as there may
   * be a separate response control for each.
   *
   * @return  The identifier that may be used to correlate this uniqueness
   *          response control with the corresponding request control.
   */
  @NotNull()
  public String getUniquenessID()
  {
    return uniquenessID;
  }



  /**
   * Retrieves the result of the server's pre-commit validation processing.
   * The same information can be inferred from the
   * {@link #getPreCommitValidationPassed()} method, but this method may provide
   * a more intuitive result and does not have the possibility of a {@code null}
   * return value.
   *
   * @return  {@link UniquenessValidationResult#VALIDATION_PASSED} if the
   *          server did not find any conflicting entries during the pre-commit
   *          check, {@link UniquenessValidationResult#VALIDATION_FAILED} if
   *          the server found at least one conflicting entry during the
   *          pre-commit check, or
   *          {@link UniquenessValidationResult#VALIDATION_NOT_ATTEMPTED} if
   *          the server did not attempt any pre-commit validation.
   */
  @NotNull()
  public UniquenessValidationResult getPreCommitValidationResult()
  {
    if (preCommitValidationPassed == null)
    {
      return UniquenessValidationResult.VALIDATION_NOT_ATTEMPTED;
    }
    else if (preCommitValidationPassed)
    {
      return UniquenessValidationResult.VALIDATION_PASSED;
    }
    else
    {
      return UniquenessValidationResult.VALIDATION_FAILED;
    }
  }



  /**
   * Retrieves a value that indicates whether pre-commit validation was
   * attempted, and whether that validation passed.  Note that this method is
   * still supported and is not deprecated at this time, but the
   * {@link #getPreCommitValidationResult()} is now the recommended way to get
   * this information.
   *
   * @return  {@code Boolean.TRUE} if pre-commit validation was attempted and
   *          passed, {@code Boolean.FALSE} if pre-commit validation was
   *          attempted and did not pass, or {@code null} if pre-commit
   *          validation was not attempted.
   */
  @Nullable()
  public Boolean getPreCommitValidationPassed()
  {
    return preCommitValidationPassed;
  }



  /**
   * Retrieves the result of the server's post-commit validation processing.
   * The same information can be inferred from the
   * {@link #getPostCommitValidationPassed()} method, but this method may
   * provide a more intuitive result and does not have the possibility of a
   * {@code null} return value.
   *
   * @return  {@link UniquenessValidationResult#VALIDATION_PASSED} if the
   *          server did not find any conflicting entries during the post-commit
   *          check, {@link UniquenessValidationResult#VALIDATION_FAILED} if
   *          the server found at least one conflicting entry during the
   *          post-commit check, or
   *          {@link UniquenessValidationResult#VALIDATION_NOT_ATTEMPTED} if
   *          the server did not attempt any post-commit validation.
   */
  @NotNull()
  public UniquenessValidationResult getPostCommitValidationResult()
  {
    if (postCommitValidationPassed == null)
    {
      return UniquenessValidationResult.VALIDATION_NOT_ATTEMPTED;
    }
    else if (postCommitValidationPassed)
    {
      return UniquenessValidationResult.VALIDATION_PASSED;
    }
    else
    {
      return UniquenessValidationResult.VALIDATION_FAILED;
    }
  }



  /**
   * Retrieves a value that indicates whether post-commit validation was
   * attempted, and whether that validation passed.
   *
   * @return  {@code Boolean.TRUE} if post-commit validation was attempted and
   *          passed, {@code Boolean.FALSE} if post-commit validation was
   *          attempted and did not pass, or {@code null} if post-commit
   *          validation was not attempted.
   */
  @Nullable()
  public Boolean getPostCommitValidationPassed()
  {
    return postCommitValidationPassed;
  }



  /**
   * Retrieves a message with additional information about the validation
   * processing that was performed.
   *
   * @return  A message with additional information about the validation
   *          processing that was performed, or {@code null} if no validation
   *          message is available.
   */
  @Nullable()
  public String getValidationMessage()
  {
    return validationMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_UNIQUENESS_RES_CONTROL_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("UniquenessResponseControl(uniquenessID='");
    buffer.append(uniquenessID);
    buffer.append("', preCommitValidationResult='");
    buffer.append(getPreCommitValidationResult().getName());
    buffer.append("', preCommitValidationResult='");
    buffer.append(getPostCommitValidationResult().getName());
    buffer.append('\'');

    if (validationMessage != null)
    {
      buffer.append(", validationMessage='");
      buffer.append(validationMessage);
      buffer.append('\'');
    }
    buffer.append(')');
  }
}
