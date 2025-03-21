/*
 * Copyright 2017-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2025 Ping Identity Corporation
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
 * Copyright (C) 2017-2025 Ping Identity Corporation
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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONBoolean;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides a request control that may be included in an add, modify,
 * or modify DN request to ensure that the contents of that request will not
 * result in a uniqueness conflict with any other entry in the server.  Each
 * instance of this control should define exactly one uniqueness constraint for
 * the associated operation.  Multiple instances of this control can be included
 * in the same request to define multiple independent uniqueness constraints
 * that must all be satisfied.  If any of the uniqueness constraints is not
 * satisfied, then the corresponding LDAP result should have a result code of
 * {@link ResultCode#ASSERTION_FAILED} and a {@link UniquenessResponseControl}
 * for each uniqueness constraint that was not satisfied.
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
 * The request properties must contain either one or more attribute types, a
 * filter, or both.  If only a filter is specified, then the server will use
 * that filter to identify conflicts (for an add request, any matches at all
 * will be considered a conflict; for a modify or modify DN request, any matches
 * with any entry other than the one being updated will be considered a
 * conflict).  If a single attribute type is specified with no filter, then any
 * change that would result in multiple entries having the same value for that
 * attribute will be considered a conflict.  If multiple attribute types are
 * specified, then the multiple attribute behavior will be used to determine how
 * to identify conflicts, as documented in the
 * {@link UniquenessMultipleAttributeBehavior} enum.  If both a set of attribute
 * types and a filter are provided, then only entries matching both sets of
 * criteria will be considered a conflict.
 * <BR><BR>
 * The server can perform two different searches in an attempt to identify
 * conflicts.  In the pre-commit phase, it will attempt to identify any
 * conflicts that already exist, and will reject the associated change if there
 * are any.  In the post-commit phase, it can see if there were any conflicts
 * introduced by the change itself or by another change happening at the same
 * time.  If a conflict is detected in the post-commit phase, then the server
 * won't have prevented it, but at least the control can be used to provide
 * notification about it.  The server may also raise an administrative alert to
 * notify administrators about the conflict.
 * <BR><BR>
 * Although post-commit validation on its own should be able to detect conflicts
 * that arise as a result of concurrent changes in other instances, it is also
 * possible to take additional measures to help prevent conflicts from arising
 * in the first place.  The control may indicate that the server should create
 * a temporary conflict prevention details entry before beginning pre-commit
 * validation processing.  This entry may be found during pre-commit validation
 * performed for any conflicting concurrent updates so that the conflicting
 * operation is rejected.  This temporary entry will be automatically removed
 * after uniqueness processing has completed, regardless of its success or
 * failure.
 * <BR><BR>
 * This request control may be sent either directly to a Directory Server
 * instance, or it may be sent to a Directory Proxy Server with or without entry
 * balancing.  If the request is sent directly to a Directory Server, then only
 * that one server will be checked for uniqueness conflicts, and it is possible
 * that concurrent conflicts may be introduced on other servers that have not
 * yet been replicated by the time control processing has completed.  If the
 * request is sent to a Directory Proxy Server instance, then search may be
 * processed in one or more backend servers based on the pre-commit and
 * post-commit validation levels, and at the most paranoid levels, it is highly
 * unlikely that any conflicts will go unnoticed.
 * <BR><BR>
 * The request control has an OID of 1.3.6.1.4.1.30221.2.5.52, a criticality of
 * either {@code true} or {@code false}, and a value with the following
 * encoding:
 * <PRE>
 *   UniquenessRequestValue ::= SEQUENCE {
 *     uniquenessID                            [0] OCTET STRING,
 *     attributeTypes                          [1] SET OF OCTET STRING OPTIONAL,
 *     multipleAttributeBehavior               [2] ENUMERATED {
 *       uniqueWithinEachAttribute                      (0),
 *       uniqueAcrossAllAttributesIncludingInSameEntry  (1),
 *       uniqueAcrossAllAttributesExceptInSameEntry     (2),
 *       uniqueInCombination                            (3),
 *       ... } DEFAULT uniqueWithinEachAttribute,
 *     baseDN                                  [3] LDAPDN OPTIONAL,
 *     filter                                  [4] Filter OPTIONAL,
 *     preventConflictsWithSoftDeletedEntries  [5] BOOLEAN DEFAULT FALSE,
 *     preCommitValidationLevel                [6] ENUMERATED {
 *       none                        (0),
 *       allSubtreeViews             (1),
 *       allBackendSets              (2),
 *       allAvailableBackendServers  (3),
 *       ... } DEFAULT allSubtreeViews,
 *     postCommitValidationLevel               [7] ENUMERATED {
 *       none                        (0),
 *       allSubtreeViews             (1),
 *       allBackendSets              (2),
 *       allAvailableBackendServers  (3),
 *       ... } DEFAULT allSubtreeViews,
 *     alertOnPostCommitConflictDetection      [8] BOOLEAN DEFAULT TRUE,
 *     createConflictPreventionDetailsEntry    [9] BOOLEAN DEFAULT FALSE,
 *     ... }
 * </PRE>
 * <BR><BR>
 * <H2>Example</H2>
 * The following example demonstrates how to use the uniqueness request control
 * to only process an add operation if it does not result in multiple entries
 * that have the same uid value:
 * <BR><BR>
 * <PRE>
 * // Create the properties to build a uniqueness request control that
 * // will try to prevent an add operation from creating a new entry
 * // that has the same uid as an existing entry in the server.  During
 * // pre-commit processing (which happens before the server actually
 * // processes the add), the server will check at least one server in
 * // each entry-balancing backend set (or just one server in a
 * // non-entry-balanced deployment).  During post-commit processing
 * // (which happens if the add succeeds), the server will double-check
 * // that no conflicting entry was added on any available server in the
 * // topology.  Also ensure that the server will not allow conflicts
 * // with soft-deleted entries.
 * final UniquenessRequestControlProperties uniquenessProperties =
 *      new UniquenessRequestControlProperties("uid");
 * uniquenessProperties.setPreCommitValidationLevel(
 *      UniquenessValidationLevel.ALL_BACKEND_SETS);
 * uniquenessProperties.setPostCommitValidationLevel(
 *      UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS);
 * uniquenessProperties.setPreventConflictsWithSoftDeletedEntries(true);
 *
 * // Create the request control.  It will be critical so that the
 * // server will not attempt to process the add if it can't honor the
 * // uniqueness request.
 * final boolean isCritical = true;
 * final String uniquenessID = "uid-uniqueness";
 * final UniquenessRequestControl uniquenessRequestControl =
 *      new UniquenessRequestControl(isCritical, uniquenessID,
 *           uniquenessProperties);
 *
 * // Attach the control to an add request.
 * addRequest.addControl(uniquenessRequestControl);
 *
 * // Send the add request to the server and read the result.
 * try
 * {
 *   final LDAPResult addResult = connection.add(addRequest);
 *
 *   // The add operation succeeded, so the entry should have been
 *   // created, but there is still the possibility that a post-commit
 *   // conflict was discovered, indicating that another request
 *   // processed at about the same time as our add introduced a
 *   // conflicting entry.
 *   final Map&lt;String,UniquenessResponseControl&gt; uniquenessResponses;
 *   try
 *   {
 *     uniquenessResponses = UniquenessResponseControl.get(addResult);
 *   }
 *   catch (final LDAPException e)
 *   {
 *     throw new RuntimeException(
 *          "The add succeeded, but an error occurred while trying " +
 *               "to decode a uniqueness response control in add " +
 *               "result " + addResult + ":  " +
 *               StaticUtils.getExceptionMessage(e),
 *          e);
 *   }
 *
 *   final UniquenessResponseControl uniquenessResponseControl =
 *        uniquenessResponses.get(uniquenessID);
 *   if ((uniquenessResponseControl != null) &amp;&amp;
 *        uniquenessResponseControl.uniquenessConflictFound())
 *   {
 *     throw new RuntimeException(
 *          "The add succeeded, but a uniqueness conflict was found  " +
 *               "Uniqueness validation message:  " +
 *               uniquenessResponseControl.getValidationMessage());
 *   }
 * }
 * catch (final LDAPException e)
 * {
 *   // The add attempt failed.  It might have been because of a
 *   // uniqueness problem, or it could have been for some other reason.
 *   // To figure out which it was, look to see if there is an
 *   // appropriate uniqueness response control.
 *   final Map&lt;String, UniquenessResponseControl&gt; uniquenessResponses;
 *   try
 *   {
 *     uniquenessResponses =
 *          UniquenessResponseControl.get(e.toLDAPResult());
 *   }
 *   catch (final LDAPException e2)
 *   {
 *     throw new LDAPException(e.getResultCode(),
 *          "The add attempt failed with result " + e.toLDAPResult() +
 *               ", and an error occurred while trying to decode a " +
 *               "uniqueness response control in the result:  " +
 *               StaticUtils.getExceptionMessage(e2),
 *          e);
 *   }
 *
 *   final UniquenessResponseControl uniquenessResponseControl =
 *        uniquenessResponses.get(uniquenessID);
 *   if (uniquenessResponseControl == null)
 *   {
 *     // The add result didn't include a uniqueness response control,
 *     // indicating that the failure was not because of a uniqueness
 *     // conflict.
 *     throw e;
 *   }
 *
 *   if (uniquenessResponseControl.uniquenessConflictFound())
 *   {
 *     // The add failed, and the uniqueness response control indicates
 *     // that the failure was because of a uniqueness conflict.
 *
 *     final UniquenessValidationResult preCommitResult =
 *          uniquenessResponseControl.getPreCommitValidationResult();
 *     final UniquenessValidationResult postCommitResult =
 *          uniquenessResponseControl.getPreCommitValidationResult();
 *     final String validationMessage =
 *          uniquenessResponseControl.getValidationMessage();
 *
 *     throw e;
 *   }
 *   else
 *   {
 *     // The add failed, but the uniqueness response control indicates
 *     // that the failure was not because of a uniqueness conflict.
 *     throw e;
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class UniquenessRequestControl
       extends Control
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.52) for the uniqueness request control.
   */
  @NotNull public static final String UNIQUENESS_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.5.52";



  /**
   * The BER type for the uniqueness ID element in the value sequence.
   */
  private static final byte TYPE_UNIQUENESS_ID = (byte) 0x80;



  /**
   * The BER type for the attribute types element in the value sequence.
   */
  private static final byte TYPE_ATTRIBUTE_TYPES = (byte) 0xA1;



  /**
   * The BER type for the multiple attribute behavior element in the value
   * sequence.
   */
  private static final byte TYPE_MULTIPLE_ATTRIBUTE_BEHAVIOR = (byte) 0x82;



  /**
   * The BER type for the base DN element in the value sequence.
   */
  private static final byte TYPE_BASE_DN = (byte) 0x83;



  /**
   * The BER type for the filter element in the value sequence.
   */
  private static final byte TYPE_FILTER = (byte) 0xA4;



  /**
   * The BER type for the prevent conflicts with soft-deleted entries element in
   * the value sequence.
   */
  private static final byte TYPE_PREVENT_CONFLICTS_WITH_SOFT_DELETED_ENTRIES =
       (byte) 0x85;



  /**
   * The BER type for the pre-commit validation element in the value sequence.
   */
  private static final byte TYPE_PRE_COMMIT_VALIDATION_LEVEL = (byte) 0x86;



  /**
   * The BER type for the post-commit validation element in the value sequence.
   */
  private static final byte TYPE_POST_COMMIT_VALIDATION_LEVEL = (byte) 0x87;



  /**
   * The BER type for the value sequence element that indicates whether to
   * raise an administrative alert if a conflict is detected during post-commit
   * validation.
   */
  private static final byte TYPE_ALERT_ON_POST_VALIDATION_CONFLICT_DETECTION =
       (byte) 0x88;



  /**
   * The BER type for the value sequence element that indicates whether to
   * create a conflict prevention details entry before pre-commit validation as
   * a means of helping to avoid conflicts.
   */
  private static final byte TYPE_CREATE_CONFLICT_PREVENTION_DETAILS_ENTRY =
       (byte) 0x89;



  /**
   * The name of the field used to hold the
   * alert-on-post-commit-conflict-detection flag in the JSON representation of
   * this control.
   */
  @NotNull private static final String
       JSON_FIELD_ALERT_ON_POST_COMMIT_CONFLICT_DETECTION =
            "alert-on-post-commit-conflict-detection";



  /**
   * The name of the field used to hold the attribute types in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_ATTRIBUTE_TYPES =
       "attribute-types";



  /**
   * The name of the field used to hold the base DN in the JSON representation
   * of this control.
   */
  @NotNull private static final String JSON_FIELD_BASE_DN = "base-dn";



  /**
   * The name of the field used to hold the
   * create-conflict-prevention-details-entry flag in the JSON representation of
   * this control.
   */
  @NotNull private static final String
       JSON_FIELD_CREATE_CONFLICT_PREVENTION_DETAILS_ENTRY =
            "create-conflict-prevention-details-entry";



  /**
   * The name of the field used to hold the filter in the JSON representation of
   * this control.
   */
  @NotNull private static final String JSON_FIELD_FILTER = "filter";



  /**
   * The name of the field used to hold the multiple attribute behavior in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_MULTIPLE_ATTRIBUTE_BEHAVIOR =
       "multiple-attribute-behavior";



  /**
   * The name of the field used to hold the pre-commit validation level in the
   * JSON representation of this control.
   */
  @NotNull private static final String  JSON_FIELD_PRE_COMMIT_VALIDATION_LEVEL =
       "pre-commit-validation-level";



  /**
   * The name of the field used to hold the post-commit validation level in the
   * JSON representation of this control.
   */
  @NotNull private static final String
       JSON_FIELD_POST_COMMIT_VALIDATION_LEVEL = "post-commit-validation-level";



  /**
   * The name of the field used to hold the
   * prevent-conflicts-with-soft-deleted-entries flag in the JSON representation
   * of this control.
   */
  @NotNull private static final String
       JSON_FIELD_PREVENT_CONFLICTS_WITH_SOFT_DELETED_ENTRIES =
            "prevent-conflicts-with-soft-deleted-entries";



  /**
   * The name of the field used to hold the uniqueness ID in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_FIELD_UNIQUENESS_ID =
       "uniqueness-id";



  /**
   * The unique-within-each-attribute multiple-attribute-behavior value to use
   * in the JSON representation of this control.
   */
  @NotNull private static final String JSON_MAB_UNIQUE_WITHIN_EACH_ATTRIBUTE =
       "unique-within-each-attribute";



  /**
   * The unique-across-all-attributes-including-in-the-same-entry
   * multiple-attribute-behavior value to use in the JSON representation of this
   * control.
   */
  @NotNull private static final String
       JSON_MAB_UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_SAME_ENTRY =
            "unique-across-all-attributes-including-in-the-same-entry";



  /**
   * The unique-across-all-attributes-except-in-the-same-entry
   * multiple-attribute-behavior value to use in the JSON representation of this
   * control.
   */
  @NotNull private static final String
       JSON_MAB_UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_SAME_ENTRY =
            "unique-across-all-attributes-except-in-the-same-entry";



  /**
   * The unique-in-combination multiple-attribute-behavior value to use in the
   * JSON representation of this control.
   */
  @NotNull private static final String JSON_MAB_UNIQUE_IN_COMBINATION =
       "unique-in-combination";



  /**
   * The none validation level value to use in the JSON representation of this
   * control.
   */
  @NotNull private static final String JSON_VALIDATION_LEVEL_NONE = "none";



  /**
   * The all-subtree-views validation level value to use in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_VALIDATION_LEVEL_ALL_SUBTREE_VIEWS =
       "all-subtree-views";



  /**
   * The all-backend-sets validation level value to use in the JSON
   * representation of this control.
   */
  @NotNull private static final String JSON_VALIDATION_LEVEL_ALL_BACKEND_SETS =
       "all-backend-sets";



  /**
   * The all-available-backend-servers validation level value to use in the JSON
   * representation of this control.
   */
  @NotNull private static final String
       JSON_VALIDATION_LEVEL_ALL_AVAILABLE_BACKEND_SERVERS =
            "all-available-backend-servers";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7976218379635922852L;



  // Indicates whether the server should raise an administrative alert if a
  // conflict is detected during post-commit validation.
  private final boolean alertOnPostCommitConflictDetection;

  // Indicates whether the server should create a conflict prevention details
  // entry before pre-commit validation as a means of helping to avoid
  // conflicts.
  private final boolean createConflictPreventionDetailsEntry;

  // Indicates whether to prevent conflicts with soft-deleted entries.
  private final boolean preventConflictsWithSoftDeletedEntries;

  // An optional filter that should be used in the course of identifying
  // uniqueness conflicts.
  @Nullable private final Filter filter;

  // A potentially-empty set of attribute types that should be checked for
  // uniqueness conflicts.
  @NotNull private final Set<String> attributeTypes;

  // An optional base DN to use when checking for conflicts.
  @Nullable private final String baseDN;

  // A value that will be used to correlate this request control with its
  // corresponding response control.
  @NotNull private final String uniquenessID;

  // The behavior that the server should exhibit if multiple attribute types
  // are configured.
  @NotNull private final UniquenessMultipleAttributeBehavior
       multipleAttributeBehavior;

  // The level of validation that the server should perform before processing
  // the associated change.
  @NotNull private final UniquenessValidationLevel postCommitValidationLevel;

  // The level of validation that the server should perform after processing the
  // associated change.
  @NotNull private final UniquenessValidationLevel preCommitValidationLevel;



  /**
   * Creates a new uniqueness request control with the provided information.
   *
   * @param  isCritical    Indicates whether the control should be considered
   *                       critical.
   * @param  uniquenessID  A value that will be used to correlate this request
   *                       control with its corresponding response control.  If
   *                       this is {@code null}, then a unique identifier will
   *                       be automatically generated.
   * @param  properties    The set of properties for this control.  It must not
   *                       be {@code null}.
   *
   * @throws  LDAPException  If the provided properties cannot be used to create
   *                         a valid uniqueness request control.
   */
  public UniquenessRequestControl(final boolean isCritical,
              @Nullable final String uniquenessID,
              @NotNull final UniquenessRequestControlProperties properties)
         throws LDAPException
  {
    this((uniquenessID == null
              ? CryptoHelper.getRandomUUID().toString()
              : uniquenessID),
         properties, isCritical);
  }



  /**
   * Creates a new uniqueness request control with the provided information.
   * Note that this version of the constructor takes the same set of arguments
   * as the above constructor, but in a different order (to distinguish between
   * the two versions), and with the additional constraint that the uniqueness
   * ID must not be {@code null}.
   *
   * @param  uniquenessID  A value that will be used to correlate this request
   *                       control with its corresponding response control.  It
   *                       must not be {@code null}.
   * @param  properties    The set of properties for this control.  It must not
   *                       be {@code null}.
   * @param  isCritical    Indicates whether the control should be considered
   *                       critical.
   *
   * @throws  LDAPException  If the provided properties cannot be used to create
   *                         a valid uniqueness request control.
   */
  private UniquenessRequestControl(@NotNull final String uniquenessID,
               @NotNull final UniquenessRequestControlProperties properties,
               final boolean isCritical)
          throws LDAPException
  {
    super(UNIQUENESS_REQUEST_OID, isCritical,
         encodeValue(uniquenessID, properties));

    Validator.ensureNotNull(uniquenessID);
    this.uniquenessID = uniquenessID;

    attributeTypes = properties.getAttributeTypes();
    multipleAttributeBehavior = properties.getMultipleAttributeBehavior();
    baseDN = properties.getBaseDN();
    filter = properties.getFilter();
    preventConflictsWithSoftDeletedEntries =
         properties.preventConflictsWithSoftDeletedEntries();
    preCommitValidationLevel = properties.getPreCommitValidationLevel();
    postCommitValidationLevel = properties.getPostCommitValidationLevel();
    alertOnPostCommitConflictDetection =
         properties.alertOnPostCommitConflictDetection();
    createConflictPreventionDetailsEntry =
         properties.createConflictPreventionDetailsEntry();

    if (attributeTypes.isEmpty() && (filter == null))
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_UNIQUENESS_REQ_NO_ATTRS_OR_FILTER.get());
    }
  }



  /**
   * Encodes the provided information into an octet string that is suitable for
   * use as the value of this control.
   *
   * @param  uniquenessID  A value that will be used to correlate this request
   *                       control with its corresponding response control.  It
   *                       must not be {@code null}.
   * @param  properties    The set of properties for this control.  It must not
   *                       be {@code null}.
   *
   * @return  The encoded value that was created.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String uniquenessID,
       @NotNull final UniquenessRequestControlProperties properties)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(10);

    elements.add(new ASN1OctetString(TYPE_UNIQUENESS_ID, uniquenessID));

    final Set<String> attributeTypes = properties.getAttributeTypes();
    if (!attributeTypes.isEmpty())
    {
      final ArrayList<ASN1Element> attributeTypeElements =
           new ArrayList<>(attributeTypes.size());
      for (final String attributeType : attributeTypes)
      {
        attributeTypeElements.add(new ASN1OctetString(attributeType));
      }
      elements.add(new ASN1Set(TYPE_ATTRIBUTE_TYPES, attributeTypeElements));
    }

    final UniquenessMultipleAttributeBehavior multipleAttributeBehavior =
         properties.getMultipleAttributeBehavior();
    if (multipleAttributeBehavior !=
         UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE)
    {
      elements.add(new ASN1Enumerated(TYPE_MULTIPLE_ATTRIBUTE_BEHAVIOR,
           multipleAttributeBehavior.intValue()));
    }

    final String baseDN = properties.getBaseDN();
    if (baseDN != null)
    {
      elements.add(new ASN1OctetString(TYPE_BASE_DN, baseDN));
    }

    final Filter filter = properties.getFilter();
    if (filter != null)
    {
      elements.add(new ASN1Element(TYPE_FILTER, filter.encode().encode()));
    }

    if (properties.preventConflictsWithSoftDeletedEntries())
    {
      elements.add(new ASN1Boolean(
           TYPE_PREVENT_CONFLICTS_WITH_SOFT_DELETED_ENTRIES, true));
    }

    final UniquenessValidationLevel preCommitValidationLevel =
         properties.getPreCommitValidationLevel();
    if (preCommitValidationLevel != UniquenessValidationLevel.ALL_SUBTREE_VIEWS)
    {
      elements.add(new ASN1Enumerated(TYPE_PRE_COMMIT_VALIDATION_LEVEL,
           preCommitValidationLevel.intValue()));
    }

    final UniquenessValidationLevel postCommitValidationLevel =
         properties.getPostCommitValidationLevel();
    if (postCommitValidationLevel !=
         UniquenessValidationLevel.ALL_SUBTREE_VIEWS)
    {
      elements.add(new ASN1Enumerated(TYPE_POST_COMMIT_VALIDATION_LEVEL,
           postCommitValidationLevel.intValue()));
    }

    if (! properties.alertOnPostCommitConflictDetection())
    {
      elements.add(new ASN1Boolean(
           TYPE_ALERT_ON_POST_VALIDATION_CONFLICT_DETECTION, false));
    }

    if (properties.createConflictPreventionDetailsEntry())
    {
      elements.add(new ASN1Boolean(
           TYPE_CREATE_CONFLICT_PREVENTION_DETAILS_ENTRY, true));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Creates a new uniqueness request control that is decoded from the provided
   * generic control.
   *
   * @param  control  The control to be decoded as a uniqueness request control.
   *                  It must not be {@code null}.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         valid uniqueness request control.
   */
  public UniquenessRequestControl(@NotNull final Control control)
         throws LDAPException
  {
    super(control);

    final ASN1OctetString value = control.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_UNIQUENESS_REQ_DECODE_NO_VALUE.get());
    }

    try
    {
      boolean decodedAlertOnPostCommitConflictDetection = true;
      boolean decodedCreateConflictPreventionDetailsEntry = false;
      boolean decodedPreventSoftDeletedConflicts = false;
      Filter decodedFilter = null;
      Set<String> decodedAttributeTypes = Collections.emptySet();
      String decodedBaseDN = null;
      String decodedUniquenessID = null;
      UniquenessMultipleAttributeBehavior decodedMultipleAttributeBehavior =
           UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE;
      UniquenessValidationLevel decodedPreCommitLevel =
           UniquenessValidationLevel.ALL_SUBTREE_VIEWS;
      UniquenessValidationLevel decodedPostCommitLevel =
           UniquenessValidationLevel.ALL_SUBTREE_VIEWS;

      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      for (final ASN1Element e : elements)
      {
        switch (e.getType())
        {
          case TYPE_UNIQUENESS_ID:
            decodedUniquenessID =
                 ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_ATTRIBUTE_TYPES:
            final ASN1Element[] atElements = ASN1Set.decodeAsSet(e).elements();
            final LinkedHashSet<String> atNames = new LinkedHashSet<>(
                 StaticUtils.computeMapCapacity(atElements.length));
            for (final ASN1Element atElement : atElements)
            {
              atNames.add(ASN1OctetString.decodeAsOctetString(
                   atElement).stringValue());
            }
            decodedAttributeTypes = Collections.unmodifiableSet(atNames);
            break;
          case TYPE_MULTIPLE_ATTRIBUTE_BEHAVIOR:
            final int mabIntValue =
                 ASN1Enumerated.decodeAsEnumerated(e).intValue();
            decodedMultipleAttributeBehavior =
                 UniquenessMultipleAttributeBehavior.valueOf(mabIntValue);
            if (decodedMultipleAttributeBehavior == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_UNIQUENESS_REQ_DECODE_UNKNOWN_MULTIPLE_ATTR_BEHAVIOR.get(
                        mabIntValue));
            }
            break;
          case TYPE_BASE_DN:
            decodedBaseDN =
                 ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_FILTER:
            decodedFilter = Filter.decode(ASN1Element.decode(e.getValue()));
            break;
          case TYPE_PREVENT_CONFLICTS_WITH_SOFT_DELETED_ENTRIES:
            decodedPreventSoftDeletedConflicts =
                 ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_PRE_COMMIT_VALIDATION_LEVEL:
            final int preCommitIntValue =
                 ASN1Enumerated.decodeAsEnumerated(e).intValue();
            decodedPreCommitLevel =
                 UniquenessValidationLevel.valueOf(preCommitIntValue);
            if (decodedPreCommitLevel == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_UNIQUENESS_REQ_DECODE_UNKNOWN_PRE_COMMIT_LEVEL.get(
                        preCommitIntValue));
            }
            break;
          case TYPE_POST_COMMIT_VALIDATION_LEVEL:
            final int postCommitIntValue =
                 ASN1Enumerated.decodeAsEnumerated(e).intValue();
            decodedPostCommitLevel =
                 UniquenessValidationLevel.valueOf(postCommitIntValue);
            if (decodedPostCommitLevel == null)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_UNIQUENESS_REQ_DECODE_UNKNOWN_POST_COMMIT_LEVEL.get(
                        postCommitIntValue));
            }
            break;
          case TYPE_ALERT_ON_POST_VALIDATION_CONFLICT_DETECTION:
            decodedAlertOnPostCommitConflictDetection =
                 ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          case TYPE_CREATE_CONFLICT_PREVENTION_DETAILS_ENTRY:
            decodedCreateConflictPreventionDetailsEntry =
                 ASN1Boolean.decodeAsBoolean(e).booleanValue();
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_UNIQUENESS_REQ_DECODE_UNKNOWN_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }

      if (decodedUniquenessID == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_UNIQUENESS_REQ_MISSING_UNIQUENESS_ID.get());
      }

      if (decodedAttributeTypes.isEmpty() && (decodedFilter == null))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_UNIQUENESS_REQ_NO_ATTRS_OR_FILTER.get());
      }

      uniquenessID = decodedUniquenessID;
      attributeTypes = decodedAttributeTypes;
      multipleAttributeBehavior = decodedMultipleAttributeBehavior;
      baseDN = decodedBaseDN;
      filter = decodedFilter;
      preventConflictsWithSoftDeletedEntries =
           decodedPreventSoftDeletedConflicts;
      preCommitValidationLevel = decodedPreCommitLevel;
      postCommitValidationLevel = decodedPostCommitLevel;
      alertOnPostCommitConflictDetection =
           decodedAlertOnPostCommitConflictDetection;
      createConflictPreventionDetailsEntry =
           decodedCreateConflictPreventionDetailsEntry;
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
           ERR_UNIQUENESS_REQ_DECODE_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the uniqueness identifier for this control, which may be used to
   * identify the response control that corresponds to this request control.
   * This is primarily useful for requests that contain multiple uniqueness
   * controls, as there may be a separate response control for each.
   *
   * @return  The uniqueness identifier for this control.
   */
  @NotNull()
  public String getUniquenessID()
  {
    return uniquenessID;
  }



  /**
   * Retrieves the set of attribute types that the server will check for
   * uniqueness conflicts.
   *
   * @return  The set of attribute types that the server will check for
   *          uniqueness conflicts, or an empty set if only a filter should be
   *          used to identify conflicts.
   */
  @NotNull()
  public Set<String> getAttributeTypes()
  {
    return attributeTypes;
  }



  /**
   * Retrieves the behavior that the server should exhibit if multiple attribute
   * types are configured.
   *
   * @return  The behavior that the server should exhibit if multiple attribute
   *          types are configured.
   */
  @NotNull()
  public UniquenessMultipleAttributeBehavior getMultipleAttributeBehavior()
  {
    return multipleAttributeBehavior;
  }



  /**
   * Retrieves the base DN that will be used for searches used to identify
   * uniqueness conflicts, if defined.
   *
   * @return  The base DN that will be used for searches used to identify
   *          uniqueness conflicts, or {@code null} if the server should search
   *          below all public naming contexts.
   */
  @Nullable()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves a filter that will be used to identify uniqueness conflicts, if
   * defined.
   *
   * @return  A filter that will be used to identify uniqueness conflicts, or
   *          {@code null} if no filter has been defined.
   */
  @Nullable()
  public Filter getFilter()
  {
    return filter;
  }



  /**
   * Indicates whether the server should attempt to identify conflicts with
   * soft-deleted entries.
   *
   * @return  {@code true} if the server should identify conflicts with both
   *          regular entries and soft-deleted entries, or {@code false} if the
   *          server should only identify conflicts with regular entries.
   */
  public boolean preventConflictsWithSoftDeletedEntries()
  {
    return preventConflictsWithSoftDeletedEntries;
  }



  /**
   * Retrieves the pre-commit validation level, which will be used to identify
   * any conflicts before the associated request is processed.
   *
   * @return  The pre-commit validation level.
   */
  @NotNull()
  public UniquenessValidationLevel getPreCommitValidationLevel()
  {
    return preCommitValidationLevel;
  }



  /**
   * Retrieves the post-commit validation level, which will be used to identify
   * any conflicts that were introduced by the request with which the control is
   * associated, or by some other concurrent changed processed in the server.
   *
   * @return  The post-commit validation level.
   */
  @NotNull()
  public UniquenessValidationLevel getPostCommitValidationLevel()
  {
    return postCommitValidationLevel;
  }



  /**
   * Indicates whether the server should raise an administrative alert if a
   * conflict is detected during post-commit validation processing.
   *
   * @return  {@code true} if the server should raise an administrative alert if
   *          a conflict is detected during post-commit validation processing,
   *          or {@code false} if not.
   */
  public boolean alertOnPostCommitConflictDetection()
  {
    return alertOnPostCommitConflictDetection;
  }



  /**
   * Indicates whether the server should create a temporary conflict prevention
   * details entry before beginning pre-commit validation to provide better
   * support for preventing conflicts.  If created, the entry will be removed
   * after post-commit validation processing has completed.
   *
   * @return  {@code true} if the server should create a temporary conflict
   *          prevention details entry before beginning pre-commit validation,
   *          or {@code false} if not.
   */
  public boolean createConflictPreventionDetailsEntry()
  {
    return createConflictPreventionDetailsEntry;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_UNIQUENESS_REQ_CONTROL_NAME.get();
  }



  /**
   * Retrieves a representation of this uniqueness request control as a JSON
   * object.  The JSON object uses the following fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the uniqueness request control, the
   *     OID is "1.3.6.1.4.1.30221.2.5.52".
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
   *     base64-encoded representation of the raw value for this uniqueness
   *     request control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this uniqueness request
   *     control.  Exactly one of the {@code value-base64} and
   *     {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code uniqueness-id} -- An optional string field that holds a
   *         unique identifier for this uniqueness control instance.
   *       </LI>
   *       <LI>
   *         {@code attribute-types} -- An optional array field whose values are
   *         the names of the attribute types for which to impose uniqueness.
   *         It may be empty or absent if uniqueness should only be enforced
   *         using a filter.
   *       </LI>
   *       <LI>
   *         {@code multiple-attribute-behavior} -- An optional string field
   *         whose value indicates the behavior that should be used if multiple
   *         unique attribute types are requested.  If present, the value should
   *         be one of "{@code unique-within-each-attribute}",
   *         "{@code unique-across-all-attributes-including-in-the-same-entry}",
   *         "{@code unique-across-all-attributes-except-in-the-same-entry}", or
   *         "{@code unique-in-combination}".
   *       </LI>
   *       <LI>
   *         {@code base-dn} -- An optional string field whose value is the base
   *         DN that will be used for searches used to identify uniqueness
   *         conflicts.
   *       </LI>
   *       <LI>
   *         {@code filter} -- An optional string field whose value is the
   *         string representation of a search filter that will be used to
   *         identify uniqueness conflicts.
   *       </LI>
   *       <LI>
   *         {@code prevent-conflicts-with-soft-deleted-entries} -- An optional
   *         Boolean field that indicates whether the server should consider
   *         soft-deleted entries when looking for conflicts.
   *       </LI>
   *       <LI>
   *         {@code pre-commit-validation-level} -- A mandatory string field
   *         whose value specifies the level of validation that the server
   *         should perform before attempting to apply the change.  The value
   *         must be one of "{@code none}", "{@code all-subtree-views}",
   *         "{@code all-backend-sets}", or
   *         "{@code all-available-backend-servers}".
   *       </LI>
   *       <LI>
   *         {@code post-commit-validation-level} -- A mandatory string field
   *         whose value specifies the level of validation that the server
   *         should perform after applying the change.  The value must be one of
   *         "{@code none}", "{@code all-subtree-views}",
   *         "{@code all-backend-sets}", or
   *         "{@code all-available-backend-servers}".
   *       </LI>
   *       <LI>
   *         {@code alert-on-post-commit-conflict-detection} -- An optional
   *         Boolean field that indicates whether the server should raise an
   *         administrative alert if a conflict was detected after the change
   *         was applied.
   *       </LI>
   *       <LI>
   *         {@code create-conflict-prevention-details-entry} -- An optional
   *         Boolean field that indicates whether the server should create a
   *         temporary entry that can improve its ability to detect conflicts
   *         before they happen.
   *       </LI>
   *     </UL>
   *   </LI>
   * </UL>
   *
   * @return  A JSON object that contains a representation of this control.
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final Map<String,JSONValue> valueFields = new LinkedHashMap<>();
    valueFields.put(JSON_FIELD_UNIQUENESS_ID, new JSONString(uniquenessID));

    if (! attributeTypes.isEmpty())
    {
      final List<JSONValue> attributeTypesValues =
           new ArrayList<>(attributeTypes.size());
      for (final String attributeType : attributeTypes)
      {
        attributeTypesValues.add(new JSONString(attributeType));
      }
      valueFields.put(JSON_FIELD_ATTRIBUTE_TYPES,
           new JSONArray(attributeTypesValues));
    }

    if ((attributeTypes.size() > 1) ||
         (multipleAttributeBehavior != UniquenessMultipleAttributeBehavior.
              UNIQUE_WITHIN_EACH_ATTRIBUTE))
    {
      switch (multipleAttributeBehavior)
      {
        case UNIQUE_WITHIN_EACH_ATTRIBUTE:
          valueFields.put(JSON_FIELD_MULTIPLE_ATTRIBUTE_BEHAVIOR,
               new JSONString(JSON_MAB_UNIQUE_WITHIN_EACH_ATTRIBUTE));
          break;
        case UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_IN_SAME_ENTRY:
          valueFields.put(JSON_FIELD_MULTIPLE_ATTRIBUTE_BEHAVIOR,
               new JSONString(
               JSON_MAB_UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_SAME_ENTRY));
          break;
        case UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_IN_SAME_ENTRY:
          valueFields.put(JSON_FIELD_MULTIPLE_ATTRIBUTE_BEHAVIOR,
               new JSONString(
                    JSON_MAB_UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_SAME_ENTRY));
          break;
        case UNIQUE_IN_COMBINATION:
          valueFields.put(JSON_FIELD_MULTIPLE_ATTRIBUTE_BEHAVIOR,
               new JSONString(JSON_MAB_UNIQUE_IN_COMBINATION));
          break;
      }
    }

    if (baseDN != null)
    {
      valueFields.put(JSON_FIELD_BASE_DN, new JSONString(baseDN));
    }

    if (filter != null)
    {
      valueFields.put(JSON_FIELD_FILTER, new JSONString(filter.toString()));
    }

    valueFields.put(JSON_FIELD_PREVENT_CONFLICTS_WITH_SOFT_DELETED_ENTRIES,
         new JSONBoolean(preventConflictsWithSoftDeletedEntries));

    addJSONValidationLevel(valueFields, JSON_FIELD_PRE_COMMIT_VALIDATION_LEVEL,
         preCommitValidationLevel);

    addJSONValidationLevel(valueFields, JSON_FIELD_POST_COMMIT_VALIDATION_LEVEL,
         postCommitValidationLevel);

    valueFields.put(JSON_FIELD_ALERT_ON_POST_COMMIT_CONFLICT_DETECTION,
         new JSONBoolean(alertOnPostCommitConflictDetection));

    valueFields.put(JSON_FIELD_CREATE_CONFLICT_PREVENTION_DETAILS_ENTRY,
         new JSONBoolean(createConflictPreventionDetailsEntry));

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              UNIQUENESS_REQUEST_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_UNIQUENESS_REQ_CONTROL_NAME.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Updates the provided map with a JSON field for the given validation level.
   *
   * @param  valueFields      The map to which the field should be added.  It
   *                          must not be {@code null}./
   * @param  fieldName        The name to use for the field.  It must not be
   *                          {@code null}.
   * @param  validationLevel  The validation level value to use.  It must not be
   *                          {@code null}.
   */
  private static void addJSONValidationLevel(
               @NotNull final Map<String,JSONValue> valueFields,
               @NotNull final String fieldName,
               @NotNull final UniquenessValidationLevel validationLevel)
  {
    switch (validationLevel)
    {
      case NONE:
        valueFields.put(fieldName, new JSONString(JSON_VALIDATION_LEVEL_NONE));
        break;
      case ALL_SUBTREE_VIEWS:
        valueFields.put(fieldName,
             new JSONString(JSON_VALIDATION_LEVEL_ALL_SUBTREE_VIEWS));
        break;
      case ALL_BACKEND_SETS:
        valueFields.put(fieldName,
             new JSONString(JSON_VALIDATION_LEVEL_ALL_BACKEND_SETS));
        break;
      case ALL_AVAILABLE_BACKEND_SERVERS:
        valueFields.put(fieldName, new JSONString(
             JSON_VALIDATION_LEVEL_ALL_AVAILABLE_BACKEND_SERVERS));
        break;
    }
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a
   * uniqueness request control.
   *
   * @param  controlObject  The JSON object to be decoded.  It must not be
   *                        {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON object contains any unrecognized
   *                        fields.  If this is {@code false}, then unrecognized
   *                        fields will be ignored.
   *
   * @return  The uniqueness request control that was decoded from the provided
   *          JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid uniqueness request control.
   */
  @NotNull()
  public static UniquenessRequestControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new UniquenessRequestControl(new Control(
           jsonControl.getOID(), jsonControl.getCriticality(), rawValue));
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final String uniquenessID =
         valueObject.getFieldAsString(JSON_FIELD_UNIQUENESS_ID);

    final Set<String> attributeTypes;
    final List<JSONValue> attributeTypesValues =
         valueObject.getFieldAsArray(JSON_FIELD_ATTRIBUTE_TYPES);
    if ((attributeTypesValues == null) || attributeTypesValues.isEmpty())
    {
      attributeTypes = Collections.emptySet();
    }
    else
    {
      attributeTypes = new LinkedHashSet<>();
      for (final JSONValue v : attributeTypesValues)
      {
        if (v instanceof JSONString)
        {
          attributeTypes.add(((JSONString) v).stringValue());
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_UNIQUENESS_REQ_JSON_ATTR_TYPE_NOT_STRING.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_ATTRIBUTE_TYPES));
        }
      }
    }

    final Filter filter;
    final String filterStr = valueObject.getFieldAsString(JSON_FIELD_FILTER);
    if (filterStr == null)
    {
      filter = null;
    }
    else
    {
      try
      {
        filter = Filter.create(filterStr);
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_UNIQUENESS_REQ_JSON_INVALID_FILTER.get(
                  controlObject.toSingleLineString(), JSON_FIELD_FILTER,
                  filterStr));
      }
    }


    final UniquenessRequestControlProperties properties;
    if (attributeTypes.isEmpty())
    {
      if (filter == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_UNIQUENESS_REQ_JSON_NEITHER_ATTR_TYPES_NOR_FILTER.get(
                  controlObject.toSingleLineString(),
                  JSON_FIELD_ATTRIBUTE_TYPES, JSON_FIELD_FILTER));
      }
      else
      {
        properties = new UniquenessRequestControlProperties(filter);
      }
    }
    else
    {
      properties = new UniquenessRequestControlProperties(attributeTypes);

      if (filter != null)
      {
        properties.setFilter(filter);
      }
    }


    final String multipleAttributeBehaviorStr =
         valueObject.getFieldAsString(JSON_FIELD_MULTIPLE_ATTRIBUTE_BEHAVIOR);
    if (multipleAttributeBehaviorStr == null)
    {
      properties.setMultipleAttributeBehavior(
           UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE);
    }
    else
    {
      switch (multipleAttributeBehaviorStr)
      {
        case JSON_MAB_UNIQUE_WITHIN_EACH_ATTRIBUTE:
          properties.setMultipleAttributeBehavior(
               UniquenessMultipleAttributeBehavior.
                    UNIQUE_WITHIN_EACH_ATTRIBUTE);
          break;
        case JSON_MAB_UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_SAME_ENTRY:
          properties.setMultipleAttributeBehavior(
               UniquenessMultipleAttributeBehavior.
                    UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_IN_SAME_ENTRY);
          break;
        case JSON_MAB_UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_SAME_ENTRY:
          properties.setMultipleAttributeBehavior(
               UniquenessMultipleAttributeBehavior.
                    UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_IN_SAME_ENTRY);
          break;
        case JSON_MAB_UNIQUE_IN_COMBINATION:
          properties.setMultipleAttributeBehavior(
               UniquenessMultipleAttributeBehavior.UNIQUE_IN_COMBINATION);
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_UNIQUENESS_REQ_JSON_UNRECOGNIZED_MULTIPLE_ATTR_BEHAVIOR.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_MULTIPLE_ATTRIBUTE_BEHAVIOR,
                    multipleAttributeBehaviorStr,
                    JSON_MAB_UNIQUE_WITHIN_EACH_ATTRIBUTE,
                    JSON_MAB_UNIQUE_ACROSS_ALL_ATTRIBUTES_INCLUDING_SAME_ENTRY,
                    JSON_MAB_UNIQUE_ACROSS_ALL_ATTRIBUTES_EXCEPT_SAME_ENTRY,
                    JSON_MAB_UNIQUE_IN_COMBINATION));
      }
    }


    final String baseDNStr = valueObject.getFieldAsString(JSON_FIELD_BASE_DN);
    if (baseDNStr != null)
    {
      properties.setBaseDN(baseDNStr);
    }


    final Boolean preventConflictsWithSoftDeletedEntries =
         valueObject.getFieldAsBoolean(
              JSON_FIELD_PREVENT_CONFLICTS_WITH_SOFT_DELETED_ENTRIES);
    if (preventConflictsWithSoftDeletedEntries == null)
    {
      properties.setPreventConflictsWithSoftDeletedEntries(false);
    }
    else
    {
      properties.setPreventConflictsWithSoftDeletedEntries(
           preventConflictsWithSoftDeletedEntries);
    }


    properties.setPreCommitValidationLevel(getValidationLevelJSON(
         controlObject, valueObject, JSON_FIELD_PRE_COMMIT_VALIDATION_LEVEL));


    properties.setPostCommitValidationLevel(getValidationLevelJSON(
         controlObject, valueObject, JSON_FIELD_POST_COMMIT_VALIDATION_LEVEL));


    final Boolean alertOnPostCommitConflictDetection =
         valueObject.getFieldAsBoolean(
              JSON_FIELD_ALERT_ON_POST_COMMIT_CONFLICT_DETECTION);
    if (alertOnPostCommitConflictDetection == null)
    {
      properties.setAlertOnPostCommitConflictDetection(true);
    }
    else
    {
      properties.setAlertOnPostCommitConflictDetection(
           alertOnPostCommitConflictDetection);
    }


    final Boolean createConflictPreventionDetailsEntry =
         valueObject.getFieldAsBoolean(
              JSON_FIELD_CREATE_CONFLICT_PREVENTION_DETAILS_ENTRY);
    if (createConflictPreventionDetailsEntry == null)
    {
      properties.setCreateConflictPreventionDetailsEntry(false);
    }
    else
    {
      properties.setCreateConflictPreventionDetailsEntry(
           createConflictPreventionDetailsEntry);
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_UNIQUENESS_ID,
                JSON_FIELD_ATTRIBUTE_TYPES,
                JSON_FIELD_MULTIPLE_ATTRIBUTE_BEHAVIOR,
                JSON_FIELD_BASE_DN, JSON_FIELD_FILTER,
                JSON_FIELD_PREVENT_CONFLICTS_WITH_SOFT_DELETED_ENTRIES,
                JSON_FIELD_PRE_COMMIT_VALIDATION_LEVEL,
                JSON_FIELD_POST_COMMIT_VALIDATION_LEVEL,
                JSON_FIELD_ALERT_ON_POST_COMMIT_CONFLICT_DETECTION,
                JSON_FIELD_CREATE_CONFLICT_PREVENTION_DETAILS_ENTRY);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_UNIQUENESS_REQ_JSON_UNRECOGNIZED_FIELD.get(
                  controlObject.toSingleLineString(),
                  unrecognizedFields.get(0)));
      }
    }


    return new UniquenessRequestControl(jsonControl.getCriticality(),
         uniquenessID, properties);
  }



  /**
   * Retrieves the uniqueness validation level value contained in the specified
   * field of the given value object.
   *
   * @param  controlObject  The JSON object containing an encoded representation
   *                        of the control being decoded.  It must not be
   *                        {@code null}.
   * @param  valueObject    The JSON object from which the value is to be
   *                        retrieved.  It must not be {@code null}.
   * @param  fieldName      The name of the field that is expected to contain
   *                        the value.  It must not be {@code null}.
   *
   * @return  The uniqueness validation level value that was retrieved.
   *
   * @throws  LDAPException  If the value object does not have a valid
   *                         uniqueness validation level value in the specified
   *                         field.
   */
  @NotNull()
  private static UniquenessValidationLevel getValidationLevelJSON(
               @NotNull final JSONObject controlObject,
               @NotNull final JSONObject valueObject,
               @NotNull final String fieldName)
          throws LDAPException
  {
    final String valueStr = valueObject.getFieldAsString(fieldName);
    if (valueStr == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_UNIQUENESS_REQ_JSON_MISSING_FIELD.get(
                controlObject.toSingleLineString(), fieldName));
    }

    switch (valueStr)
    {
      case JSON_VALIDATION_LEVEL_NONE:
        return UniquenessValidationLevel.NONE;
      case JSON_VALIDATION_LEVEL_ALL_SUBTREE_VIEWS:
        return UniquenessValidationLevel.ALL_SUBTREE_VIEWS;
      case JSON_VALIDATION_LEVEL_ALL_BACKEND_SETS:
        return UniquenessValidationLevel.ALL_BACKEND_SETS;
      case JSON_VALIDATION_LEVEL_ALL_AVAILABLE_BACKEND_SERVERS:
        return UniquenessValidationLevel.ALL_AVAILABLE_BACKEND_SERVERS;
      default:
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_UNIQUENESS_REQ_JSON_UNRECOGNIZED_VALIDATION_LEVEL.get(
                  controlObject.toSingleLineString(), fieldName, valueStr,
                  JSON_VALIDATION_LEVEL_NONE,
                  JSON_VALIDATION_LEVEL_ALL_SUBTREE_VIEWS,
                  JSON_VALIDATION_LEVEL_ALL_BACKEND_SETS,
                  JSON_VALIDATION_LEVEL_ALL_AVAILABLE_BACKEND_SERVERS));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("UniquenessRequestControl(isCritical=");
    buffer.append(isCritical());
    buffer.append(", uniquenessID='");
    buffer.append(uniquenessID);
    buffer.append("', attributeTypes={");

    final Iterator<String> attributeTypesIterator = attributeTypes.iterator();
    while (attributeTypesIterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(attributeTypesIterator.next());
      buffer.append('\'');

      if (attributeTypesIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, multipleAttributeBehavior=");
    buffer.append(multipleAttributeBehavior);

    if (baseDN != null)
    {
      buffer.append(", baseDN='");
      buffer.append(baseDN);
      buffer.append('\'');
    }

    if (filter != null)
    {
      buffer.append(", filter='");
      buffer.append(filter);
      buffer.append('\'');
    }

    buffer.append(", preventConflictsWithSoftDeletedEntries=");
    buffer.append(preventConflictsWithSoftDeletedEntries);
    buffer.append(", preCommitValidationLevel=");
    buffer.append(preCommitValidationLevel);
    buffer.append(", postCommitValidationLevel=");
    buffer.append(postCommitValidationLevel);
    buffer.append(", alertOnPostCommitConflictDetection=");
    buffer.append(alertOnPostCommitConflictDetection);
    buffer.append(", createConflictPreventionDetailsEntry=");
    buffer.append(createConflictPreventionDetailsEntry);
    buffer.append(')');
  }
}
