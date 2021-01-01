/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.args;



import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.controls.DontUseCopyRequestControl;
import com.unboundid.ldap.sdk.controls.DraftLDUPSubentriesRequestControl;
import com.unboundid.ldap.sdk.controls.ManageDsaITRequestControl;
import com.unboundid.ldap.sdk.controls.PermissiveModifyRequestControl;
import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;
import com.unboundid.ldap.sdk.experimental.
            DraftBeheraLDAPPasswordPolicy10RequestControl;
import com.unboundid.ldap.sdk.experimental.
            DraftZeilengaLDAPNoOp12RequestControl;
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class defines an argument that is intended to hold information about one
 * or more LDAP controls.  Values for this argument must be in one of the
 * following formats:
 * <UL>
 *   <LI>
 *     oid -- The numeric OID for the control.  The control will not be critical
 *     and will not have a value.
 *   </LI>
 *   <LI>
 *     oid:criticality -- The numeric OID followed by a colon and the
 *     criticality.  The control will be critical if the criticality value is
 *     any of the following:  {@code true}, {@code t}, {@code yes}, {@code y},
 *     {@code on}, or {@code 1}.  The control will be non-critical if the
 *     criticality value is any of the following:  {@code false}, {@code f},
 *     {@code no}, {@code n}, {@code off}, or {@code 0}.  No other criticality
 *     values will be accepted.
 *   </LI>
 *   <LI>
 *     oid:criticality:value -- The numeric OID followed by a colon and the
 *     criticality, then a colon and then a string that represents the value for
 *     the control.
 *   </LI>
 *   <LI>
 *     oid:criticality::base64value -- The numeric OID  followed by a colon and
 *     the criticality, then two colons and then a string that represents the
 *     base64-encoded value for the control.
 *   </LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ControlArgument
       extends Argument
{
  /**
   * A map of human-readable names to the corresponding numeric OIDs.
   */
  @NotNull private static final Map<String,String> OIDS_BY_NAME;
  static
  {
    final HashMap<String,String> oidsByName =
         new HashMap<>(StaticUtils.computeMapCapacity(100));

    // The authorization identity request control.
    oidsByName.put("authzid",
         AuthorizationIdentityRequestControl.
              AUTHORIZATION_IDENTITY_REQUEST_OID);
    oidsByName.put("authorizationidentity",
         AuthorizationIdentityRequestControl.
              AUTHORIZATION_IDENTITY_REQUEST_OID);
    oidsByName.put("authorization-identity",
         AuthorizationIdentityRequestControl.
              AUTHORIZATION_IDENTITY_REQUEST_OID);

    // The don't use copy request control.
    oidsByName.put("nocopy",
         DontUseCopyRequestControl.DONT_USE_COPY_REQUEST_OID);
    oidsByName.put("dontusecopy",
         DontUseCopyRequestControl.DONT_USE_COPY_REQUEST_OID);
    oidsByName.put("no-copy",
         DontUseCopyRequestControl.DONT_USE_COPY_REQUEST_OID);
    oidsByName.put("dont-use-copy",
         DontUseCopyRequestControl.DONT_USE_COPY_REQUEST_OID);

    // The LDAP no-operation request control.
    oidsByName.put("noop",
         DraftZeilengaLDAPNoOp12RequestControl.NO_OP_REQUEST_OID);
    oidsByName.put("nooperation",
         DraftZeilengaLDAPNoOp12RequestControl.NO_OP_REQUEST_OID);
    oidsByName.put("no-op",
         DraftZeilengaLDAPNoOp12RequestControl.NO_OP_REQUEST_OID);
    oidsByName.put("no-operation",
         DraftZeilengaLDAPNoOp12RequestControl.NO_OP_REQUEST_OID);

    // The LDAP subentries request control as described in
    // draft-ietf-ldup-subentry.
    oidsByName.put("subentries",
         DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);
    oidsByName.put("ldapsubentries",
         DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);
    oidsByName.put("ldap-subentries",
         DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);
    oidsByName.put("ldupsubentries",
         DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);
    oidsByName.put("ldup-subentries",
         DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);
    oidsByName.put("draftldupsubentries",
         DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);
    oidsByName.put("draft-ldup-subentries",
         DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);
    oidsByName.put("draftietfldupsubentries",
         DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);
    oidsByName.put("draft-ietf-ldup-subentries",
         DraftLDUPSubentriesRequestControl.SUBENTRIES_REQUEST_OID);

    // The manage DSA IT request control.
    oidsByName.put("managedsait",
         ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID);
    oidsByName.put("manage-dsa-it",
         ManageDsaITRequestControl.MANAGE_DSA_IT_REQUEST_OID);

    // The permissive modify request control.
    oidsByName.put("permissivemodify",
         PermissiveModifyRequestControl.PERMISSIVE_MODIFY_REQUEST_OID);
    oidsByName.put("permissive-modify",
         PermissiveModifyRequestControl.PERMISSIVE_MODIFY_REQUEST_OID);

    // The password policy request control.
    oidsByName.put("pwpolicy",
         DraftBeheraLDAPPasswordPolicy10RequestControl.
              PASSWORD_POLICY_REQUEST_OID);
    oidsByName.put("passwordpolicy",
         DraftBeheraLDAPPasswordPolicy10RequestControl.
              PASSWORD_POLICY_REQUEST_OID);
    oidsByName.put("pw-policy",
         DraftBeheraLDAPPasswordPolicy10RequestControl.
              PASSWORD_POLICY_REQUEST_OID);
    oidsByName.put("password-policy",
         DraftBeheraLDAPPasswordPolicy10RequestControl.
              PASSWORD_POLICY_REQUEST_OID);

    // The subtree delete request control.
    oidsByName.put("subtreedelete",
         SubtreeDeleteRequestControl.SUBTREE_DELETE_REQUEST_OID);
    oidsByName.put("treedelete",
         SubtreeDeleteRequestControl.SUBTREE_DELETE_REQUEST_OID);
    oidsByName.put("subtree-delete",
         SubtreeDeleteRequestControl.SUBTREE_DELETE_REQUEST_OID);
    oidsByName.put("tree-delete",
         SubtreeDeleteRequestControl.SUBTREE_DELETE_REQUEST_OID);

    // The account usable request control.
    oidsByName.put("accountusable", "1.3.6.1.4.1.42.2.27.9.5.8");
    oidsByName.put("accountusability", "1.3.6.1.4.1.42.2.27.9.5.8");
    oidsByName.put("account-usable", "1.3.6.1.4.1.42.2.27.9.5.8");
    oidsByName.put("account-usability", "1.3.6.1.4.1.42.2.27.9.5.8");

    // The generate password request control.
    oidsByName.put("generatepassword", "1.3.6.1.4.1.30221.2.5.58");
    oidsByName.put("generate-password", "1.3.6.1.4.1.30221.2.5.58");
    oidsByName.put("generatepw", "1.3.6.1.4.1.30221.2.5.58");
    oidsByName.put("generate-pw", "1.3.6.1.4.1.30221.2.5.58");

    // The get backend set ID request control.
    oidsByName.put("backendsetid", "1.3.6.1.4.1.30221.2.5.33");
    oidsByName.put("getbackendsetid", "1.3.6.1.4.1.30221.2.5.33");
    oidsByName.put("backendset-id", "1.3.6.1.4.1.30221.2.5.33");
    oidsByName.put("backend-set-id", "1.3.6.1.4.1.30221.2.5.33");
    oidsByName.put("get-backendset-id", "1.3.6.1.4.1.30221.2.5.33");
    oidsByName.put("get-backend-set-id", "1.3.6.1.4.1.30221.2.5.33");

    // The get effective rights request control.
    oidsByName.put("effectiverights", "1.3.6.1.4.1.42.2.27.9.5.2");
    oidsByName.put("geteffectiverights", "1.3.6.1.4.1.42.2.27.9.5.2");
    oidsByName.put("effective-rights", "1.3.6.1.4.1.42.2.27.9.5.2");
    oidsByName.put("get-effective-rights", "1.3.6.1.4.1.42.2.27.9.5.2");

    // The get password policy state issues request control.
    oidsByName.put("pwpolicystateissues", "1.3.6.1.4.1.30221.2.5.46");
    oidsByName.put("getpwpolicystateissues", "1.3.6.1.4.1.30221.2.5.46");
    oidsByName.put("passwordpolicystateissues", "1.3.6.1.4.1.30221.2.5.46");
    oidsByName.put("getpasswordpolicystateissues", "1.3.6.1.4.1.30221.2.5.46");
    oidsByName.put("pw-policy-state-issues", "1.3.6.1.4.1.30221.2.5.46");
    oidsByName.put("get-pw-policy-state-issues", "1.3.6.1.4.1.30221.2.5.46");
    oidsByName.put("password-policy-state-issues", "1.3.6.1.4.1.30221.2.5.46");
    oidsByName.put("get-password-policy-state-issues",
         "1.3.6.1.4.1.30221.2.5.46");

    // The get recent login history request control.
    oidsByName.put("loginhistory", "1.3.6.1.4.1.30221.2.5.61");
    oidsByName.put("recentloginhistory", "1.3.6.1.4.1.30221.2.5.61");
    oidsByName.put("getrecentloginhistory", "1.3.6.1.4.1.30221.2.5.61");
    oidsByName.put("login-history", "1.3.6.1.4.1.30221.2.5.61");
    oidsByName.put("recent-login-history", "1.3.6.1.4.1.30221.2.5.61");
    oidsByName.put("get-recent-login-history", "1.3.6.1.4.1.30221.2.5.61");

    // The get server ID request control.
    oidsByName.put("serverid", "1.3.6.1.4.1.30221.2.5.14");
    oidsByName.put("getserverid", "1.3.6.1.4.1.30221.2.5.14");
    oidsByName.put("server-id", "1.3.6.1.4.1.30221.2.5.14");
    oidsByName.put("get-server-id", "1.3.6.1.4.1.30221.2.5.14");

    // The get user resource limits request control.
    oidsByName.put("userresourcelimits", "1.3.6.1.4.1.30221.2.5.25");
    oidsByName.put("getuserresourcelimits", "1.3.6.1.4.1.30221.2.5.25");
    oidsByName.put("user-resource-limits", "1.3.6.1.4.1.30221.2.5.25");
    oidsByName.put("get-user-resource-limits", "1.3.6.1.4.1.30221.2.5.25");

    // The hard delete request control.
    oidsByName.put("harddelete", "1.3.6.1.4.1.30221.2.5.22");
    oidsByName.put("hard-delete", "1.3.6.1.4.1.30221.2.5.22");

    // The ignore NO-USER-MODIFICATION request control.
    oidsByName.put("ignorenousermod", "1.3.6.1.4.1.30221.2.5.5");
    oidsByName.put("ignorenousermodification", "1.3.6.1.4.1.30221.2.5.5");
    oidsByName.put("ignore-no-user-mod", "1.3.6.1.4.1.30221.2.5.5");
    oidsByName.put("ignore-no-user-modification", "1.3.6.1.4.1.30221.2.5.5");

    // The purge retired password request control.
    oidsByName.put("purgepassword", "1.3.6.1.4.1.30221.2.5.32");
    oidsByName.put("purgeretiredpassword", "1.3.6.1.4.1.30221.2.5.32");
    oidsByName.put("purge-password", "1.3.6.1.4.1.30221.2.5.32");
    oidsByName.put("purge-retired-password", "1.3.6.1.4.1.30221.2.5.32");

    // The real attributes only request control.
    oidsByName.put("realattrsonly", "2.16.840.1.113730.3.4.17");
    oidsByName.put("realattributesonly", "2.16.840.1.113730.3.4.17");
    oidsByName.put("real-attrs-only", "2.16.840.1.113730.3.4.17");
    oidsByName.put("real-attributes-only", "2.16.840.1.113730.3.4.17");

    // The replication repair request control.
    oidsByName.put("replrepair", "1.3.6.1.4.1.30221.1.5.2");
    oidsByName.put("replicationrepair", "1.3.6.1.4.1.30221.1.5.2");
    oidsByName.put("repl-repair", "1.3.6.1.4.1.30221.1.5.2");
    oidsByName.put("replication-repair", "1.3.6.1.4.1.30221.1.5.2");

    // The retain identity request control.
    oidsByName.put("retainidentity", "1.3.6.1.4.1.30221.2.5.3");
    oidsByName.put("retain-identity", "1.3.6.1.4.1.30221.2.5.3");

    // The retire password request control.
    oidsByName.put("retirepassword", "1.3.6.1.4.1.30221.2.5.31");
    oidsByName.put("retire-password", "1.3.6.1.4.1.30221.2.5.31");

    // The return conflict entries request control.
    oidsByName.put("returnconflictentries", "1.3.6.1.4.1.30221.2.5.13");
    oidsByName.put("return-conflict-entries", "1.3.6.1.4.1.30221.2.5.13");

    // The soft delete request control.
    oidsByName.put("softdelete", "1.3.6.1.4.1.30221.2.5.20");
    oidsByName.put("soft-delete", "1.3.6.1.4.1.30221.2.5.20");

    // The soft-deleted entry access request control.
    oidsByName.put("softdeleteentryaccess", "1.3.6.1.4.1.30221.2.5.24");
    oidsByName.put("softdeletedentryaccess", "1.3.6.1.4.1.30221.2.5.24");
    oidsByName.put("soft-delete-entry-access", "1.3.6.1.4.1.30221.2.5.24");
    oidsByName.put("soft-deleted-entry-access", "1.3.6.1.4.1.30221.2.5.24");

    // The suppress referential integrity updates request control.
    oidsByName.put("suppressreferentialintegrity", "1.3.6.1.4.1.30221.2.5.30");
    oidsByName.put("suppressreferentialintegrityupdates",
         "1.3.6.1.4.1.30221.2.5.30");
    oidsByName.put("suppress-referential-integrity",
         "1.3.6.1.4.1.30221.2.5.30");
    oidsByName.put("suppress-referential-integrity-updates",
         "1.3.6.1.4.1.30221.2.5.30");

    // The undelete request control.
    oidsByName.put("undelete", "1.3.6.1.4.1.30221.2.5.23");

    // The virtual attributes only request control.
    oidsByName.put("virtualattrsonly", "2.16.840.1.113730.3.4.19");
    oidsByName.put("virtualattributesonly", "2.16.840.1.113730.3.4.19");
    oidsByName.put("virtual-attrs-only", "2.16.840.1.113730.3.4.19");
    oidsByName.put("virtual-attributes-only", "2.16.840.1.113730.3.4.19");

    OIDS_BY_NAME = Collections.unmodifiableMap(oidsByName);
  }



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1889200072476038957L;



  // The argument value validators that have been registered for this argument.
  @NotNull private final List<ArgumentValueValidator> validators;

  // The list of default values for this argument.
  @Nullable private final List<Control> defaultValues;

  // The set of values assigned to this argument.
  @NotNull private final List<Control> values;



  /**
   * Creates a new control argument with the provided information.  It will not
   * be required, will be allowed any number of times, will use a default
   * placeholder, and will not have a default value.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public ControlArgument(@Nullable final Character shortIdentifier,
                         @Nullable final String longIdentifier,
                         @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, false, 0, null, description);
  }



  /**
   * Creates a new control argument with the provided information.  It will not
   * have a default value.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
   * @param  maxOccurrences    The maximum number of times this argument may be
   *                           provided on the command line.  A value less than
   *                           or equal to zero indicates that it may be present
   *                           any number of times.
   * @param  valuePlaceholder  A placeholder to display in usage information to
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} to use a default placeholder that
   *                           describes the expected syntax for values.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public ControlArgument(@Nullable final Character shortIdentifier,
                         @Nullable final String longIdentifier,
                         final boolean isRequired,
                         final int maxOccurrences,
                         @Nullable final String valuePlaceholder,
                         @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         valuePlaceholder, description, (List<Control>) null);
  }



  /**
   * Creates a new control argument with the provided information.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
   * @param  maxOccurrences    The maximum number of times this argument may be
   *                           provided on the command line.  A value less than
   *                           or equal to zero indicates that it may be present
   *                           any number of times.
   * @param  valuePlaceholder  A placeholder to display in usage information to
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} to use a default placeholder that
   *                           describes the expected syntax for values.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  defaultValue      The default value to use for this argument if no
   *                           values were provided.  It may be {@code null} if
   *                           there should be no default values.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public ControlArgument(@Nullable final Character shortIdentifier,
                         @Nullable final String longIdentifier,
                         final boolean isRequired,
                         final int maxOccurrences,
                         @Nullable final String valuePlaceholder,
                         @NotNull final String description,
                         @Nullable final Control defaultValue)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired, maxOccurrences,
         valuePlaceholder, description,
         ((defaultValue == null)
              ? null :
              Collections.singletonList(defaultValue)));
  }



  /**
   * Creates a new control argument with the provided information.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
   * @param  maxOccurrences    The maximum number of times this argument may be
   *                           provided on the command line.  A value less than
   *                           or equal to zero indicates that it may be present
   *                           any number of times.
   * @param  valuePlaceholder  A placeholder to display in usage information to
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} to use a default placeholder that
   *                           describes the expected syntax for values.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  defaultValues     The set of default values to use for this
   *                           argument if no values were provided.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public ControlArgument(@Nullable final Character shortIdentifier,
                         @Nullable final String longIdentifier,
                         final boolean isRequired,
                         final int maxOccurrences,
                         @Nullable final String valuePlaceholder,
                         @NotNull final String description,
                         @Nullable final List<Control> defaultValues)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         (valuePlaceholder == null)
              ? INFO_PLACEHOLDER_CONTROL.get()
              : valuePlaceholder,
         description);

    if ((defaultValues == null) || defaultValues.isEmpty())
    {
      this.defaultValues = null;
    }
    else
    {
      this.defaultValues = Collections.unmodifiableList(defaultValues);
    }

    values = new ArrayList<>(5);
    validators = new ArrayList<>(5);
  }



  /**
   * Creates a new control argument that is a "clean" copy of the provided
   * source argument.
   *
   * @param  source  The source argument to use for this argument.
   */
  private ControlArgument(@NotNull final ControlArgument source)
  {
    super(source);

    defaultValues = source.defaultValues;
    validators    = new ArrayList<>(source.validators);
    values        = new ArrayList<>(5);
  }



  /**
   * Retrieves the list of default values for this argument, which will be used
   * if no values were provided.
   *
   * @return   The list of default values for this argument, or {@code null} if
   *           there are no default values.
   */
  @Nullable()
  public List<Control> getDefaultValues()
  {
    return defaultValues;
  }



  /**
   * Updates this argument to ensure that the provided validator will be invoked
   * for any values provided to this argument.  This validator will be invoked
   * after all other validation has been performed for this argument.
   *
   * @param  validator  The argument value validator to be invoked.  It must not
   *                    be {@code null}.
   */
  public void addValueValidator(@NotNull final ArgumentValueValidator validator)
  {
    validators.add(validator);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addValue(@NotNull final String valueString)
            throws ArgumentException
  {
    String oid = null;
    boolean isCritical = false;
    ASN1OctetString value = null;

    final int firstColonPos = valueString.indexOf(':');
    if (firstColonPos < 0)
    {
      oid = valueString;
    }
    else
    {
      oid = valueString.substring(0, firstColonPos);

      final String criticalityStr;
      final int secondColonPos = valueString.indexOf(':', (firstColonPos+1));
      if (secondColonPos < 0)
      {
        criticalityStr = valueString.substring(firstColonPos+1);
      }
      else
      {
        criticalityStr = valueString.substring(firstColonPos+1, secondColonPos);

        final int doubleColonPos = valueString.indexOf("::");
        if (doubleColonPos == secondColonPos)
        {
          try
          {
            value = new ASN1OctetString(
                 Base64.decode(valueString.substring(doubleColonPos+2)));
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new ArgumentException(
                 ERR_CONTROL_ARG_INVALID_BASE64_VALUE.get(valueString,
                      getIdentifierString(),
                      valueString.substring(doubleColonPos+2)),
                 e);
          }
        }
        else
        {
          value = new ASN1OctetString(valueString.substring(secondColonPos+1));
        }
      }

      final String lowerCriticalityStr =
           StaticUtils.toLowerCase(criticalityStr);
      if (lowerCriticalityStr.equals("true") ||
          lowerCriticalityStr.equals("t") ||
          lowerCriticalityStr.equals("yes") ||
          lowerCriticalityStr.equals("y") ||
          lowerCriticalityStr.equals("on") ||
          lowerCriticalityStr.equals("1"))
      {
        isCritical = true;
      }
      else if (lowerCriticalityStr.equals("false") ||
               lowerCriticalityStr.equals("f") ||
               lowerCriticalityStr.equals("no") ||
               lowerCriticalityStr.equals("n") ||
               lowerCriticalityStr.equals("off") ||
               lowerCriticalityStr.equals("0"))
      {
        isCritical = false;
      }
      else
      {
        throw new ArgumentException(ERR_CONTROL_ARG_INVALID_CRITICALITY.get(
             valueString, getIdentifierString(), criticalityStr));
      }
    }

    if (! StaticUtils.isNumericOID(oid))
    {
      final String providedOID = oid;
      oid = OIDS_BY_NAME.get(StaticUtils.toLowerCase(providedOID));
      if (oid == null)
      {
        throw new ArgumentException(ERR_CONTROL_ARG_INVALID_OID.get(
             valueString, getIdentifierString(), providedOID));
      }
    }

    if (values.size() >= getMaxOccurrences())
    {
      throw new ArgumentException(ERR_ARG_MAX_OCCURRENCES_EXCEEDED.get(
                                       getIdentifierString()));
    }

    for (final ArgumentValueValidator v : validators)
    {
      v.validateArgumentValue(this, valueString);
    }

    values.add(new Control(oid, isCritical, value));
  }



  /**
   * Retrieves the value for this argument, or the default value if none was
   * provided.  If there are multiple values, then the first will be returned.
   *
   * @return  The value for this argument, or the default value if none was
   *          provided, or {@code null} if there is no value and no default
   *          value.
   */
  @Nullable()
  public Control getValue()
  {
    if (values.isEmpty())
    {
      if ((defaultValues == null) || defaultValues.isEmpty())
      {
        return null;
      }
      else
      {
        return defaultValues.get(0);
      }
    }
    else
    {
      return values.get(0);
    }
  }



  /**
   * Retrieves the set of values for this argument, or the default values if
   * none were provided.
   *
   * @return  The set of values for this argument, or the default values if none
   *          were provided.
   */
  @NotNull()
  public List<Control> getValues()
  {
    if (values.isEmpty() && (defaultValues != null))
    {
      return defaultValues;
    }

    return Collections.unmodifiableList(values);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getValueStringRepresentations(final boolean useDefault)
  {
    final List<Control> controls;
    if (values.isEmpty())
    {
      if (useDefault)
      {
        controls = defaultValues;
      }
      else
      {
        return Collections.emptyList();
      }
    }
    else
    {
      controls = values;
    }

    if ((controls == null) || controls.isEmpty())
    {
      return Collections.emptyList();
    }

    final StringBuilder buffer = new StringBuilder();
    final ArrayList<String> valueStrings = new ArrayList<>(controls.size());
    for (final Control c : controls)
    {
      buffer.setLength(0);
      buffer.append(c.getOID());
      buffer.append(':');
      buffer.append(c.isCritical());

      if (c.hasValue())
      {
        final byte[] valueBytes = c.getValue().getValue();
        if (StaticUtils.isPrintableString(valueBytes))
        {
          buffer.append(':');
          buffer.append(c.getValue().stringValue());
        }
        else
        {
          buffer.append("::");
          Base64.encode(valueBytes, buffer);
        }
      }

      valueStrings.add(buffer.toString());
    }

    return Collections.unmodifiableList(valueStrings);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean hasDefaultValue()
  {
    return ((defaultValues != null) && (! defaultValues.isEmpty()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDataTypeName()
  {
    return INFO_CONTROL_TYPE_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getValueConstraints()
  {
    return INFO_CONTROL_CONSTRAINTS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void reset()
  {
    super.reset();
    values.clear();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ControlArgument getCleanCopy()
  {
    return new ControlArgument(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addToCommandLine(@NotNull final List<String> argStrings)
  {
    final StringBuilder buffer = new StringBuilder();
    for (final Control c : values)
    {
      argStrings.add(getIdentifierString());

      if (isSensitive())
      {
        argStrings.add("***REDACTED***");
        continue;
      }

      buffer.setLength(0);
      buffer.append(c.getOID());
      buffer.append(':');
      buffer.append(c.isCritical());

      if (c.hasValue())
      {
        final byte[] valueBytes = c.getValue().getValue();
        if (StaticUtils.isPrintableString(valueBytes))
        {
          buffer.append(':');
          buffer.append(c.getValue().stringValue());
        }
        else
        {
          buffer.append("::");
          Base64.encode(valueBytes, buffer);
        }
      }

      argStrings.add(buffer.toString());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ControlArgument(");
    appendBasicToStringInfo(buffer);

    if ((defaultValues != null) && (! defaultValues.isEmpty()))
    {
      if (defaultValues.size() == 1)
      {
        buffer.append(", defaultValue='");
        buffer.append(defaultValues.get(0).toString());
      }
      else
      {
        buffer.append(", defaultValues={");

        final Iterator<Control> iterator = defaultValues.iterator();
        while (iterator.hasNext())
        {
          buffer.append('\'');
          buffer.append(iterator.next().toString());
          buffer.append('\'');

          if (iterator.hasNext())
          {
            buffer.append(", ");
          }
        }

        buffer.append('}');
      }
    }

    buffer.append(')');
  }
}
