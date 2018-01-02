/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.asn1.ASN1Set;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

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
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
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
 * notification about it.
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
 *     ... }
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
  public static final String UNIQUENESS_REQUEST_OID =
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
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7976218379635922852L;



  // Indicates whether to prevent conflicts with soft-deleted entries.
  private final boolean preventConflictsWithSoftDeletedEntries;

  // An optional filter that should be used in the course of identifying
  // uniqueness conflicts.
  private final Filter filter;

  // A potentially-empty set of attribute types that should be checked for
  // uniqueness conflicts.
  private final Set<String> attributeTypes;

  // An optional base DN to use when checking for conflicts.
  private final String baseDN;

  // A value that will be used to correlate this request control with its
  // corresponding response control.
  private final String uniquenessID;

  // The behavior that the server should exhibit if multiple attribute types
  // are configured.
  private final UniquenessMultipleAttributeBehavior multipleAttributeBehavior;

  // The level of validation that the server should perform before processing
  // the associated change.
  private final UniquenessValidationLevel postCommitValidationLevel;

  // The level of validation that the server should perform after processing the
  // associated change.
  private final UniquenessValidationLevel preCommitValidationLevel;



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
              final String uniquenessID,
              final UniquenessRequestControlProperties properties)
         throws LDAPException
  {
    this((uniquenessID == null
              ? UUID.randomUUID().toString()
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
   * @param  isCritical    Indicates whether the control should be considered
   *                       critical.
   * @param  uniquenessID  A value that will be used to correlate this request
   *                       control with its corresponding response control.  It
   *                       must not be {@code null}.
   * @param  properties    The set of properties for this control.  It must not
   *                       be {@code null}.
   *
   * @throws  LDAPException  If the provided properties cannot be used to create
   *                         a valid uniqueness request control.
   */
  private UniquenessRequestControl(final String uniquenessID,
               final UniquenessRequestControlProperties properties,
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
  private static ASN1OctetString encodeValue(final String uniquenessID,
                      final UniquenessRequestControlProperties properties)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(8);

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
  public UniquenessRequestControl(final Control control)
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
            final LinkedHashSet<String> atNames =
                 new LinkedHashSet<>(atElements.length);
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
  public UniquenessValidationLevel getPostCommitValidationLevel()
  {
    return postCommitValidationLevel;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getControlName()
  {
    return INFO_UNIQUENESS_REQ_CONTROL_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
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
    buffer.append(')');
  }
}
