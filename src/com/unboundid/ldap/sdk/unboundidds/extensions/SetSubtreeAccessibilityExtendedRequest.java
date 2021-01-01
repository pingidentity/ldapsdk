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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that may be used
 * to set the accessibility of one or more subtrees in the Ping Identity,
 * UnboundID, or Nokia/Alcatel-Lucent 8661 Directory Server.  It may be used to
 * indicate that a specified set of entries and all their subordinates should be
 * invisible or read-only, or to restore it to full accessibility.
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
 * The OID for this request is 1.3.6.1.4.1.30221.2.6.19, and the
 * value must have the encoding specified below.  Note that the initial
 * specification for this extended request only allowed for the specification of
 * a single subtree, whereas it is now possible to affect the accessibility of
 * multiple subtrees in a single request.  In order to preserve compatibility
 * with the original encoding, if there is more than one target subtree, then
 * the first subtree must be specified as the first element in the value
 * sequence and the remaining subtrees must be specified in the
 * additionalSubtreeBaseDNs element.
 * <BR><BR>
 * <PRE>
 *   SetSubtreeAccessibilityRequestValue ::= SEQUENCE {
 *        subtreeBaseDN                LDAPDN,
 *        subtreeAccessibility         ENUMERATED {
 *             accessible                 (0),
 *             read-only-bind-allowed     (1),
 *             read-only-bind-denied      (2),
 *             hidden                     (3),
 *             ... },
 *        bypassUserDN                 [0] LDAPDN OPTIONAL,
 *        additionalSubtreeBaseDNs     [1] SEQUENCE OF LDAPDN OPTIONAL,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SetSubtreeAccessibilityExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.19) for the set subtree accessibility
   * extended request.
   */
  @NotNull public static final String SET_SUBTREE_ACCESSIBILITY_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.19";



  /**
   * The BER type for the bypass user DN element of the request.
   */
  private static final byte TYPE_BYPASS_USER_DN = (byte) 0x80;



  /**
   * The BER type for the set of additional subtree base DNs.
   */
  private static final byte TYPE_ADDITIONAL_SUBTREE_BASE_DNS = (byte) 0xA1;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3003738735546060245L;



  // The set of subtree base DNs included in the request.
  @NotNull private final List<String> subtreeBaseDNs;

  // The DN of a user who will be exempted from the restrictions.  This is not
  // applicable for a subtree accessibility of ACCESSIBLE.
  @Nullable private final String bypassUserDN;

  // The accessibility state to use for the target subtrees.
  @NotNull private final SubtreeAccessibilityState accessibilityState;



  /**
   * Creates a new set subtree accessibility extended request with the provided
   * information.
   *
   * @param  subtreeBaseDNs      The set of base DNs for the target subtree.
   *                             It must not be {@code null} or empty.
   * @param  accessibilityState  The accessibility state to use for the target
   *                             subtrees.
   * @param  bypassUserDN        The DN of a user that will be allowed to bypass
   *                             restrictions on the target subtrees.
   * @param  controls            The set of controls to include in the request.
   */
  private SetSubtreeAccessibilityExtendedRequest(
               @NotNull final Collection<String> subtreeBaseDNs,
               @NotNull final SubtreeAccessibilityState accessibilityState,
               @Nullable final String bypassUserDN,
               @Nullable final Control... controls)
  {
    super(SET_SUBTREE_ACCESSIBILITY_REQUEST_OID,
         encodeValue(subtreeBaseDNs, accessibilityState, bypassUserDN),
         controls);

    this.subtreeBaseDNs = Collections.unmodifiableList(
         new ArrayList<>(subtreeBaseDNs));
    this.accessibilityState = accessibilityState;
    this.bypassUserDN = bypassUserDN;
  }



  /**
   * Encodes the provided information for use as the extended request value.
   *
   * @param  subtreeBaseDNs      The set of base DNs for the target subtrees.
   *                             It must not be {@code null} or empty.
   * @param  accessibilityState  The accessibility state to use for the target
   *                             subtrees.
   * @param  bypassUserDN        The DN of a user that will be allowed to bypass
   *                             restrictions on the target subtrees.
   *
   * @return  An ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @NotNull final Collection<String> subtreeBaseDNs,
               @NotNull final SubtreeAccessibilityState accessibilityState,
               @Nullable final String bypassUserDN)
  {
    final Iterator<String> dnIterator = subtreeBaseDNs.iterator();
    final String subtreeBaseDN = dnIterator.next();
    Validator.ensureNotNull(subtreeBaseDN);

    final ArrayList<ASN1Element> elements = new ArrayList<>(4);
    elements.add(new ASN1OctetString(subtreeBaseDN));
    elements.add(new ASN1Enumerated(accessibilityState.intValue()));

    if (bypassUserDN != null)
    {
      elements.add(new ASN1OctetString(TYPE_BYPASS_USER_DN, bypassUserDN));
    }

    if (dnIterator.hasNext())
    {
      final ArrayList<ASN1Element> additionalDNElements =
           new ArrayList<>(subtreeBaseDNs.size()-1);
      while (dnIterator.hasNext())
      {
        final String additionalDN = dnIterator.next();
        Validator.ensureNotNull(additionalDN);
        additionalDNElements.add(new ASN1OctetString(additionalDN));
      }
      elements.add(new ASN1Sequence(TYPE_ADDITIONAL_SUBTREE_BASE_DNS,
           additionalDNElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Creates a new set subtree accessibility extended request from the provided
   * generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          set subtree accessibility extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public SetSubtreeAccessibilityExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SET_SUBTREE_ACCESSIBILITY_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();

      final List<String> baseDNs = new ArrayList<>(10);
      baseDNs.add(ASN1OctetString.decodeAsOctetString(
           elements[0]).stringValue());

      final int accessibilityStateValue =
           ASN1Enumerated.decodeAsEnumerated(elements[1]).intValue();
      accessibilityState =
           SubtreeAccessibilityState.valueOf(accessibilityStateValue);
      if (accessibilityState == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_SET_SUBTREE_ACCESSIBILITY_INVALID_ACCESSIBILITY_STATE.get(
                  accessibilityStateValue));
      }

      String bypassDN = null;
      for (int i=2; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_BYPASS_USER_DN:
            bypassDN =
                 ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
            break;

          case TYPE_ADDITIONAL_SUBTREE_BASE_DNS:
            for (final ASN1Element e :
                 ASN1Sequence.decodeAsSequence(elements[i]).elements())
            {
              baseDNs.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
            }
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_SET_SUBTREE_ACCESSIBILITY_INVALID_ELEMENT_TYPE.get(
                      StaticUtils.toHex(elements[i].getType())));
        }
      }
      bypassUserDN = bypassDN;
      subtreeBaseDNs = Collections.unmodifiableList(baseDNs);
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
           ERR_SET_SUBTREE_ACCESSIBILITY_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    if ((accessibilityState == SubtreeAccessibilityState.ACCESSIBLE) &&
        (bypassUserDN != null))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_SET_SUBTREE_ACCESSIBILITY_UNEXPECTED_BYPASS_DN.get(
                accessibilityState.getStateName()));
    }
  }



  /**
   * Creates a new set subtree accessibility extended request that will make the
   * specified subtree accessible.
   *
   * @param  subtreeBaseDN  The base DN for the subtree to make accessible.  It
   *                        must not be {@code null}.
   * @param  controls       The set of controls to include in the request.  It
   *                        may be {@code null} or empty if no controls are
   *                        needed.
   *
   * @return  The set subtree accessibility extended request that was created.
   */
  @NotNull()
  public static SetSubtreeAccessibilityExtendedRequest
              createSetAccessibleRequest(@NotNull final String subtreeBaseDN,
                                         @Nullable final Control... controls)
  {
    Validator.ensureNotNull(subtreeBaseDN);

    return new SetSubtreeAccessibilityExtendedRequest(
         Collections.singletonList(subtreeBaseDN),
         SubtreeAccessibilityState.ACCESSIBLE, null, controls);
  }



  /**
   * Creates a new set subtree accessibility extended request that will make the
   * specified subtrees accessible.
   *
   * @param  subtreeBaseDNs  The base DNs for the subtrees to make accessible.
   *                         It must not be {@code null} or empty.  If multiple
   *                         base DNs are specified, then all must reside below
   *                         the same backend base DN.
   * @param  controls        The set of controls to include in the request.  It
   *                         may be {@code null} or empty if no controls are
   *                         needed.
   *
   * @return  The set subtree accessibility extended request that was created.
   */
  @NotNull()
  public static SetSubtreeAccessibilityExtendedRequest
                     createSetAccessibleRequest(
                          @NotNull final Collection<String> subtreeBaseDNs,
                          @Nullable final Control... controls)
  {
    Validator.ensureNotNull(subtreeBaseDNs);
    Validator.ensureFalse(subtreeBaseDNs.isEmpty());

    return new SetSubtreeAccessibilityExtendedRequest(subtreeBaseDNs,
         SubtreeAccessibilityState.ACCESSIBLE, null, controls);
  }



  /**
   * Creates a new set subtree accessibility extended request that will make the
   * specified subtree read-only.
   *
   * @param  subtreeBaseDN  The base DN for the subtree to make read-only.  It
   *                        must not be {@code null}.
   * @param  allowBind      Indicates whether users within the specified subtree
   *                        will be allowed to bind.
   * @param  bypassUserDN   The DN of a user that will be allowed to perform
   *                        write (add, delete, modify, and modify DN)
   *                        operations in the specified subtree.  It may be
   *                        {@code null} if no bypass user is needed.
   * @param  controls       The set of controls to include in the request.  It
   *                        may be {@code null} or empty if no controls are
   *                        needed.
   *
   * @return  The set subtree accessibility extended request that was created.
   */
  @NotNull()
  public static SetSubtreeAccessibilityExtendedRequest
              createSetReadOnlyRequest(@NotNull final String subtreeBaseDN,
                                       final boolean allowBind,
                                       @Nullable final String bypassUserDN,
                                       @Nullable final Control... controls)
  {
    Validator.ensureNotNull(subtreeBaseDN);

    if (allowBind)
    {
      return new SetSubtreeAccessibilityExtendedRequest(
           Collections.singletonList(subtreeBaseDN),
           SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED, bypassUserDN,
           controls);
    }
    else
    {
      return new SetSubtreeAccessibilityExtendedRequest(
           Collections.singletonList(subtreeBaseDN),
           SubtreeAccessibilityState.READ_ONLY_BIND_DENIED, bypassUserDN,
           controls);
    }
  }



  /**
   * Creates a new set subtree accessibility extended request that will make the
   * specified subtrees read-only.
   *
   * @param  subtreeBaseDNs  The base DNs for the subtrees to make read-only.
   *                         It must not be {@code null} or empty.  If multiple
   *                         base DNs are specified, then all must reside below
   *                         the same backend base DN.
   * @param  allowBind       Indicates whether users within the specified
   *                         subtrees will be allowed to bind.
   * @param  bypassUserDN    The DN of a user that will be allowed to perform
   *                         write (add, delete, modify, and modify DN)
   *                         operations in the specified subtrees.  It may be
   *                         {@code null} if no bypass user is needed.
   * @param  controls        The set of controls to include in the request.  It
   *                         may be {@code null} or empty if no controls are
   *                         needed.
   *
   * @return  The set subtree accessibility extended request that was created.
   */
  @NotNull()
  public static SetSubtreeAccessibilityExtendedRequest
              createSetReadOnlyRequest(
                   @NotNull final Collection<String> subtreeBaseDNs,
                   final boolean allowBind,
                   @Nullable final String bypassUserDN,
                   @Nullable final Control... controls)
  {
    Validator.ensureNotNull(subtreeBaseDNs);
    Validator.ensureFalse(subtreeBaseDNs.isEmpty());

    if (allowBind)
    {
      return new SetSubtreeAccessibilityExtendedRequest(subtreeBaseDNs,
           SubtreeAccessibilityState.READ_ONLY_BIND_ALLOWED, bypassUserDN,
           controls);
    }
    else
    {
      return new SetSubtreeAccessibilityExtendedRequest(subtreeBaseDNs,
           SubtreeAccessibilityState.READ_ONLY_BIND_DENIED, bypassUserDN,
           controls);
    }
  }



  /**
   * Creates a new set subtree accessibility extended request that will make the
   * specified subtree hidden.
   *
   * @param  subtreeBaseDN  The base DN for the subtree to make hidden.  It must
   *                        not be {@code null}.
   * @param  bypassUserDN   The DN of a user that will be allowed to perform
   *                        write (add, delete, modify, and modify DN)
   *                        operations in the specified subtree.  It may be
   *                        {@code null} if no bypass user is needed.
   * @param  controls       The set of controls to include in the request.  It
   *                        may be {@code null} or empty if no controls are
   *                        needed.
   *
   * @return  The set subtree accessibility extended request that was created.
   */
  @NotNull()
  public static SetSubtreeAccessibilityExtendedRequest
              createSetHiddenRequest(@NotNull final String subtreeBaseDN,
                                     @Nullable final String bypassUserDN,
                                     @Nullable final Control... controls)
  {
    Validator.ensureNotNull(subtreeBaseDN);

    return new SetSubtreeAccessibilityExtendedRequest(
         Collections.singletonList(subtreeBaseDN),
         SubtreeAccessibilityState.HIDDEN, bypassUserDN, controls);
  }



  /**
   * Creates a new set subtree accessibility extended request that will make the
   * specified subtrees hidden.
   *
   * @param  subtreeBaseDNs  The base DNs for the subtrees to make hidden.  It
   *                         must not be {@code null} or empty.  If multiple
   *                         base DNs are specified, then all must reside below
   *                         the same backend base DN.
   * @param  bypassUserDN    The DN of a user that will be allowed to perform
   *                         write (add, delete, modify, and modify DN)
   *                         operations in the specified subtrees.  It may be
   *                         {@code null} if no bypass user is needed.
   * @param  controls        The set of controls to include in the request.  It
   *                         may be {@code null} or empty if no controls are
   *                         needed.
   *
   * @return  The set subtree accessibility extended request that was created.
   */
  @NotNull()
  public static SetSubtreeAccessibilityExtendedRequest
              createSetHiddenRequest(
                   @NotNull final Collection<String> subtreeBaseDNs,
                   @Nullable final String bypassUserDN,
                   @Nullable final Control... controls)
  {
    Validator.ensureNotNull(subtreeBaseDNs);
    Validator.ensureFalse(subtreeBaseDNs.isEmpty());

    return new SetSubtreeAccessibilityExtendedRequest(subtreeBaseDNs,
         SubtreeAccessibilityState.HIDDEN, bypassUserDN, controls);
  }



  /**
   * Retrieves the base DN for the target subtree.  Note that if multiple
   * base DNs are defined, this will only retrieve the first.  The
   * {@link #getSubtreeBaseDNs()} method should be used to get the complete set
   * of target subtree base DNs.
   *
   * @return  The base DN for the target subtree.
   */
  @NotNull()
  public String getSubtreeBaseDN()
  {
    return subtreeBaseDNs.get(0);
  }



  /**
   * Retrieves the base DNs for all target subtrees.
   *
   * @return  The base DNs for all target subtrees.
   */
  @NotNull()
  public List<String> getSubtreeBaseDNs()
  {
    return subtreeBaseDNs;
  }



  /**
   * Retrieves the accessibility state to apply to the target subtrees.
   *
   * @return  The accessibility state to apply to the target subtrees.
   */
  @NotNull()
  public SubtreeAccessibilityState getAccessibilityState()
  {
    return accessibilityState;
  }



  /**
   * Retrieves the DN of the user that will be allowed to bypass the
   * restrictions imposed on the target subtrees for all other users.
   *
   * @return  The DN of the user that will be allowed to bypass the restrictions
   *          imposed on the target subtrees for all other users, or
   *          {@code null} if there are no restrictions to be imposed on the
   *          target subtrees or if no bypass user is defined for those
   *          subtrees.
   */
  @Nullable()
  public String getBypassUserDN()
  {
    return bypassUserDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SetSubtreeAccessibilityExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public SetSubtreeAccessibilityExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    return new SetSubtreeAccessibilityExtendedRequest(subtreeBaseDNs,
         accessibilityState, bypassUserDN, controls);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_SET_SUBTREE_ACCESSIBILITY.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SetSubtreeAccessibilityExtendedRequest(baseDNs={");

    final Iterator<String> dnIterator = subtreeBaseDNs.iterator();
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

    buffer.append("}, accessibilityType=\"");
    buffer.append(accessibilityState.getStateName());
    buffer.append('"');

    if (bypassUserDN != null)
    {
      buffer.append(", bypassUserDN=\"");
      buffer.append(bypassUserDN);
      buffer.append('"');
    }

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
