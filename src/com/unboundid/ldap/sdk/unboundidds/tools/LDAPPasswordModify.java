/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPExtendedOperationException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RootDSE;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.UnsolicitedNotificationHandler;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedRequest;
import com.unboundid.ldap.sdk.extensions.PasswordModifyExtendedResult;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedRequest;
import com.unboundid.ldap.sdk.extensions.WhoAmIExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.controls.AssuredReplicationLocalLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRemoteLevel;
import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetAuthorizationEntryRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            GetUserResourceLimitsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.NoOpRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            OperationPurposeRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordPolicyRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.
            PasswordValidationDetailsRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.PurgePasswordRequestControl;
import com.unboundid.ldap.sdk.unboundidds.controls.RetirePasswordRequestControl;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StartAdministrativeSessionPostConnectProcessor;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.PasswordReader;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.ControlArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.DurationArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides an implementation of an LDAP command-line tool that may
 * be used to change passwords in a directory server.  Three types of password
 * changes are supported:  the password modify extended operation (as described
 * in <A HREF="http://www.ietf.org/rfc/rfc3062.txt">RFC 3062</A>), a standard
 * LDAP modify operation that targets an attribute like userPassword, or an
 * Active Directory-specific password change that uses an LDAP modify operation
 * to replace the value of the unicodePwd attribute with a value that is the
 * password surrounded by quotation marks and encoded with UTF-16-LE.
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
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class LDAPPasswordModify
       extends LDAPCommandLineTool
       implements UnsolicitedNotificationHandler
{
  /**
   * The column at which output should be wrapped.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The assured replication local level value that indicates no assurance is
   * needed.
   */
  @NotNull private static final String ASSURED_REPLICATION_LOCAL_LEVEL_NONE =
       "none";



  /**
   * The assured replication local level value that indicates the change should
   * be received by at least one other local server.
   */
  @NotNull private static final String
       ASSURED_REPLICATION_LOCAL_LEVEL_RECEIVED_ANY_SERVER =
            "received-any-server";



  /**
   * The assured replication local level value that indicates the change should
   * be processed by all available local servers.
   */
  @NotNull private static final String
       ASSURED_REPLICATION_LOCAL_LEVEL_PROCESSED_ALL_SERVERS =
            "processed-all-servers";



  /**
   * The assured replication remote level value that indicates no assurance is
   * needed.
   */
  @NotNull private static final String ASSURED_REPLICATION_REMOTE_LEVEL_NONE =
       "none";



  /**
   * The assured replication remote level value that indicates the change should
   * be received by at least one other remote server in at least one remote
   * location.
   */
  @NotNull private static final String
       ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ANY_REMOTE_LOCATION =
            "received-any-remote-location";



  /**
   * The assured replication remote level value that indicates the change should
   * be received by at least one other remote server in every remote
   * location.
   */
  @NotNull private static final String
       ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ALL_REMOTE_LOCATIONS =
            "received-all-remote-locations";



  /**
   * The assured replication remote level value that indicates the change should
   * be processed by all available remote servers in all locations.
   */
  @NotNull private static final String
       ASSURED_REPLICATION_REMOTE_LEVEL_PROCESSED_ALL_REMOTE_SERVERS =
            "processed-all-remote-servers";



  /**
   * The password change method that will be used to indicate that the password
   * modify extended operation should be used.
   */
  @NotNull private static final String PASSWORD_CHANGE_METHOD_PW_MOD_EXTOP =
       "password-modify-extended-operation";



  /**
   * The password change method that will be used to indicate that a regular
   * LDAP modify operation should be used.
   */
  @NotNull private static final String PASSWORD_CHANGE_METHOD_LDAP_MOD =
       "ldap-modify";



  /**
   * The password change method that will be used to indicate that an
   * Active Directory-specific operation should be used.
   */
  @NotNull private static final String PASSWORD_CHANGE_METHOD_AD =
       "active-directory";



  /**
   * The long identifier for the {@link LDAPCommandLineTool} argument used to
   * specify the bind DN to use when authenticating to the directory server.
   */
  @NotNull private static final String BIND_DN_ARGUMENT_LONG_IDENTIFIER =
       "bindDN";



  /**
   * The name of the default attribute that will be assumed to hold the password
   * in most directory servers.
   */
  @NotNull private static final String DEFAULT_PASSWORD_ATTRIBUTE =
       "userPassword";



  /**
   * The name of the attribute that Active Directory uses to hold the password.
   */
  @NotNull private static final String AD_PASSWORD_ATTRIBUTE = "unicodePwd";



  /**
   * The names of the attributes that will be used when searching for an entry
   * from its username in most directory servers.
   */
  @NotNull private static final List<String> DEFAULT_USERNAME_ATTRIBUTES =
       Collections.singletonList("uid");



  /**
   * The names of the attributes that will be used when searching for an entry
   * from its username in an Active Directory server.
   */
  @NotNull private static final List<String> AD_USERNAME_ATTRIBUTES =
       Collections.unmodifiableList(Arrays.asList("samAccountName",
            "userPrincipalName"));



  /**
   * The OID base that has been assigned to Microsoft.
   */
  @NotNull private static final String MICROSOFT_BASE_OBJECT_IDENTIFIER =
       "1.2.840.113556";



  // A reference to the completion message to return for this tool.
  @NotNull private final AtomicReference<String> completionMessage;

  // A reference to the argument parser for this tool.
  @Nullable private ArgumentParser argumentParser;

  // The supported command-line arguments.
  @Nullable private BooleanArgument followReferrals;
  @Nullable private BooleanArgument generateClientSideNewPassword;
  @Nullable private BooleanArgument getPasswordValidationDetails;
  @Nullable private BooleanArgument getUserResourceLimits;
  @Nullable private BooleanArgument noOperation;
  @Nullable private BooleanArgument promptForCurrentPassword;
  @Nullable private BooleanArgument promptForNewPassword;
  @Nullable private BooleanArgument provideBindDNAsUserIdentity;
  @Nullable private BooleanArgument purgeCurrentPassword;
  @Nullable private BooleanArgument retireCurrentPassword;
  @Nullable private BooleanArgument scriptFriendly;
  @Nullable private BooleanArgument useAdministrativeSession;
  @Nullable private BooleanArgument useAssuredReplication;
  @Nullable private BooleanArgument useAuthorizationIdentityControl;
  @Nullable private BooleanArgument usePasswordPolicyControlOnBind;
  @Nullable private BooleanArgument usePasswordPolicyControlOnUpdate;
  @Nullable private BooleanArgument verbose;
  @Nullable private ControlArgument bindControl;
  @Nullable private ControlArgument updateControl;
  @Nullable private DNArgument searchBaseDN;
  @Nullable private DurationArgument assuredReplicationTimeout;
  @Nullable private FileArgument currentPasswordFile;
  @Nullable private FileArgument newPasswordFile;
  @Nullable private IntegerArgument generatedPasswordLength;
  @Nullable private StringArgument assuredReplicationLocalLevel;
  @Nullable private StringArgument assuredReplicationRemoteLevel;
  @Nullable private StringArgument currentPassword;
  @Nullable private StringArgument generatedPasswordCharacterSet;
  @Nullable private StringArgument getAuthorizationEntryAttribute;
  @Nullable private StringArgument newPassword;
  @Nullable private StringArgument operationPurpose;
  @Nullable private StringArgument passwordAttribute;
  @Nullable private StringArgument passwordChangeMethod;
  @Nullable private StringArgument passwordUpdateBehavior;
  @Nullable private StringArgument userIdentity;
  @Nullable private StringArgument usernameAttribute;




  /**
   * Invokes this tool with the provided set of arguments.  The default standard
   * output and error streams will be used.
   *
   * @param  args  The command-line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Invokes this tool with the provided set of arguments, and using the
   * provided streams for standard output and error.
   *
   * @param  out   The output stream to use for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream to use for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this program.
   *
   * @return  The result code obtained when running the tool.  Any result code
   *          other than {@link ResultCode#SUCCESS} indicates an error.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final LDAPPasswordModify tool = new LDAPPasswordModify(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided output and error
   * streams.
   *
   * @param  out  The output stream to use for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream to use for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public LDAPPasswordModify(@Nullable final OutputStream out,
                            @Nullable final OutputStream err)
  {
    super(out, err);

    completionMessage = new AtomicReference<>();

    argumentParser = null;

    followReferrals = null;
    generateClientSideNewPassword = null;
    getPasswordValidationDetails = null;
    getUserResourceLimits = null;
    noOperation = null;
    promptForCurrentPassword = null;
    promptForNewPassword = null;
    provideBindDNAsUserIdentity = null;
    purgeCurrentPassword = null;
    retireCurrentPassword = null;
    scriptFriendly = null;
    useAdministrativeSession = null;
    useAssuredReplication = null;
    useAuthorizationIdentityControl = null;
    usePasswordPolicyControlOnBind = null;
    usePasswordPolicyControlOnUpdate = null;
    verbose = null;
    bindControl = null;
    updateControl = null;
    searchBaseDN = null;
    assuredReplicationTimeout = null;
    currentPasswordFile = null;
    newPasswordFile = null;
    generatedPasswordLength = null;
    assuredReplicationLocalLevel = null;
    assuredReplicationRemoteLevel = null;
    currentPassword = null;
    generatedPasswordCharacterSet = null;
    getAuthorizationEntryAttribute = null;
    newPassword = null;
    operationPurpose = null;
    passwordAttribute = null;
    passwordChangeMethod = null;
    passwordUpdateBehavior = null;
    userIdentity = null;
    usernameAttribute = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "ldappasswordmodify";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_PWMOD_TOOL_DESCRIPTION_1.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getAdditionalDescriptionParagraphs()
  {
    return Collections.unmodifiableList(Arrays.asList(
         INFO_PWMOD_TOOL_DESCRIPTION_2.get(),
         INFO_PWMOD_TOOL_DESCRIPTION_3.get(),
         INFO_PWMOD_TOOL_DESCRIPTION_4.get()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsOutputFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsAuthentication()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean defaultToPromptForBindPassword()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsSASLHelp()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean includeAlternateLongIdentifiers()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected List<Control> getBindControls()
  {
    final List<Control> bindControls = new ArrayList<>(10);

    if (bindControl.isPresent())
    {
      bindControls.addAll(bindControl.getValues());
    }

    if (useAuthorizationIdentityControl.isPresent())
    {
      bindControls.add(new AuthorizationIdentityRequestControl(false));
    }

    if (getAuthorizationEntryAttribute.isPresent())
    {
      bindControls.add(new GetAuthorizationEntryRequestControl(true, true,
           getAuthorizationEntryAttribute.getValues()));
    }

    if (getUserResourceLimits.isPresent())
    {
      bindControls.add(new GetUserResourceLimitsRequestControl());
    }

    if (usePasswordPolicyControlOnBind.isPresent())
    {
      bindControls.add(new PasswordPolicyRequestControl());
    }

    return bindControls;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsMultipleServers()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean supportsSSLDebugging()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDAPConnectionOptions getConnectionOptions()
  {
    final LDAPConnectionOptions options = new LDAPConnectionOptions();

    options.setUseSynchronousMode(true);
    options.setFollowReferrals(followReferrals.isPresent());
    options.setUnsolicitedNotificationHandler(this);
    options.setResponseTimeoutMillis(0L);

    return options;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean logToolInvocationByDefault()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  protected String getToolCompletionMessage()
  {
    return completionMessage.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    argumentParser = parser;

    // Authorization identity arguments.
    userIdentity = new StringArgument('a', "userIdentity", false, 1,
         INFO_PWMOD_ARG_PLACEHOLDER_DN_OR_AUTHZID.get(),
         INFO_PWMOD_ARG_DESC_USER_IDENTITY.get());
    userIdentity.addLongIdentifier("user-identity", true);
    userIdentity.addLongIdentifier("userDN", true);
    userIdentity.addLongIdentifier("user-dn", true);
    userIdentity.addLongIdentifier("authzID", true);
    userIdentity.addLongIdentifier("authz-id", true);
    userIdentity.addLongIdentifier("authorizationID", true);
    userIdentity.addLongIdentifier("authorization-id", true);
    userIdentity.setArgumentGroupName(INFO_PWMOD_ARG_GROUP_USER_IDENTITY.get());
    parser.addArgument(userIdentity);

    provideBindDNAsUserIdentity = new BooleanArgument('A',
         "provideBindDNAsUserIdentity", 1,
         INFO_PWMOD_ARG_DESC_PROVIDE_BIND_DN_AS_USER_IDENTITY.get());
    provideBindDNAsUserIdentity.addLongIdentifier(
         "provide-bind-dn-as-user-identity", true);
    provideBindDNAsUserIdentity.addLongIdentifier(
         "provideBindDNForUserIdentity", true);
    provideBindDNAsUserIdentity.addLongIdentifier(
         "provide-bind-dn-for-user-identity", true);
    provideBindDNAsUserIdentity.addLongIdentifier("provideDNAsUserIdentity",
         true);
    provideBindDNAsUserIdentity.addLongIdentifier("provide-dn-as-user-identity",
         true);
    provideBindDNAsUserIdentity.addLongIdentifier("provideDNForUserIdentity",
         true);
    provideBindDNAsUserIdentity.addLongIdentifier(
         "provide-dn-for-user-identity", true);
    provideBindDNAsUserIdentity.addLongIdentifier("useBindDNAsUserIdentity",
         true);
    provideBindDNAsUserIdentity.addLongIdentifier(
         "use-bind-dn-as-user-identity", true);
    provideBindDNAsUserIdentity.addLongIdentifier("useBindDNForUserIdentity",
         true);
    provideBindDNAsUserIdentity.addLongIdentifier(
         "use-bind-dn-for-user-identity", true);
    provideBindDNAsUserIdentity.addLongIdentifier("useDNAsUserIdentity", true);
    provideBindDNAsUserIdentity.addLongIdentifier("use-dn-as-user-identity",
         true);
    provideBindDNAsUserIdentity.addLongIdentifier("useDNForUserIdentity", true);
    provideBindDNAsUserIdentity.addLongIdentifier("use-dn-for-user-identity",
         true);
    provideBindDNAsUserIdentity.addLongIdentifier("useBindDNForAuthzID", true);
    provideBindDNAsUserIdentity.addLongIdentifier("use-bind-dn-for-authz-id",
         true);
    provideBindDNAsUserIdentity.addLongIdentifier("provideDNForAuthzID", true);
    provideBindDNAsUserIdentity.addLongIdentifier("provide-dn-for-authz-id",
         true);
    provideBindDNAsUserIdentity.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_USER_IDENTITY.get());
    parser.addArgument(provideBindDNAsUserIdentity);

    usernameAttribute = new StringArgument(null, "usernameAttribute", false, 0,
         INFO_PWMOD_ARG_PLACEHOLDER_ATTRIBUTE_NAME.get(),
         INFO_PWMOD_ARG_DESC_USERNAME_ATTRIBUTE.get());
    usernameAttribute.addLongIdentifier("username-attribute", true);
    usernameAttribute.addLongIdentifier("usernameAttr", true);
    usernameAttribute.addLongIdentifier("username-attr", true);
    usernameAttribute.addLongIdentifier("userIDAttribute", true);
    usernameAttribute.addLongIdentifier("user-id-attribute", true);
    usernameAttribute.addLongIdentifier("userIDAttr", true);
    usernameAttribute.addLongIdentifier("user-id-attr", true);
    usernameAttribute.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_USER_IDENTITY.get());
    parser.addArgument(usernameAttribute);

    searchBaseDN = new DNArgument('b', "searchBaseDN", false, 0, null,
         INFO_PWMOD_ARG_DESC_SEARCH_BASE_DN.get(), DN.NULL_DN);
    searchBaseDN.addLongIdentifier("search-base-dn", true);
    searchBaseDN.addLongIdentifier("baseDN", true);
    searchBaseDN.addLongIdentifier("base-dn", true);
    searchBaseDN.setArgumentGroupName(INFO_PWMOD_ARG_GROUP_USER_IDENTITY.get());
    parser.addArgument(searchBaseDN);


    // New password arguments.
    newPassword = new StringArgument('n', "newPassword", false, 1,
         INFO_PWMOD_ARG_PLACEHOLDER_PASSWORD.get(),
         INFO_PWMOD_ARG_DESC_NEW_PASSWORD.get());
    newPassword.addLongIdentifier("new-password", true);
    newPassword.addLongIdentifier("newPW", true);
    newPassword.addLongIdentifier("new-pw", true);
    newPassword.addLongIdentifier("new", true);
    newPassword.setArgumentGroupName(INFO_PWMOD_ARG_GROUP_NEW_PASSWORD.get());
    parser.addArgument(newPassword);

    newPasswordFile = new FileArgument('N', "newPasswordFile", false, 1, null,
         INFO_PWMOD_ARG_DESC_NEW_PASSWORD_FILE.get(), true, true, true, false);
    newPasswordFile.addLongIdentifier("new-password-file", true);
    newPasswordFile.addLongIdentifier("newPWFile", true);
    newPasswordFile.addLongIdentifier("new-pw-file", true);
    newPasswordFile.addLongIdentifier("newFile", true);
    newPasswordFile.addLongIdentifier("new-file", true);
    newPasswordFile.addLongIdentifier("newPasswordPath", true);
    newPasswordFile.addLongIdentifier("new-password-path", true);
    newPasswordFile.addLongIdentifier("newPWPath", true);
    newPasswordFile.addLongIdentifier("new-pw-path", true);
    newPasswordFile.addLongIdentifier("newPath", true);
    newPasswordFile.addLongIdentifier("new-path", true);
    newPasswordFile.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_NEW_PASSWORD.get());
    parser.addArgument(newPasswordFile);

    promptForNewPassword = new BooleanArgument(null, "promptForNewPassword", 1,
         INFO_PWMOD_ARG_DESC_PROMPT_FOR_NEW_PASSWORD.get());
    promptForNewPassword.addLongIdentifier("prompt-for-new-password", true);
    promptForNewPassword.addLongIdentifier("promptForNewPW", true);
    promptForNewPassword.addLongIdentifier("prompt-for-new-pw", true);
    promptForNewPassword.addLongIdentifier("promptForNew", true);
    promptForNewPassword.addLongIdentifier("prompt-for-new", true);
    promptForNewPassword.addLongIdentifier("promptNew", true);
    promptForNewPassword.addLongIdentifier("prompt-new", true);
    promptForNewPassword.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_NEW_PASSWORD.get());
    parser.addArgument(promptForNewPassword);

    generateClientSideNewPassword = new BooleanArgument(null,
         "generateClientSideNewPassword", 1,
         INFO_PWMOD_ARG_DESC_GENERATE_CLIENT_SIDE_NEW_PASSWORD.get());
    generateClientSideNewPassword.addLongIdentifier(
         "generate-client-side-new-password", true);
    generateClientSideNewPassword.addLongIdentifier("generateClientSideNewPW",
         true);
    generateClientSideNewPassword.addLongIdentifier(
         "generate-client-side-new-pw", true);
    generateClientSideNewPassword.addLongIdentifier("generateNewPassword",
         true);
    generateClientSideNewPassword.addLongIdentifier("generate-new-password",
         true);
    generateClientSideNewPassword.addLongIdentifier("generateNewPW", true);
    generateClientSideNewPassword.addLongIdentifier("generate-new-pw", true);
    generateClientSideNewPassword.addLongIdentifier("generatePassword", true);
    generateClientSideNewPassword.addLongIdentifier("generate-password", true);
    generateClientSideNewPassword.addLongIdentifier("generatePW", true);
    generateClientSideNewPassword.addLongIdentifier("generate-pw", true);
    generateClientSideNewPassword.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_NEW_PASSWORD.get());
    parser.addArgument(generateClientSideNewPassword);

    generatedPasswordLength = new IntegerArgument(null,
         "generatedPasswordLength", false, 1,
         INFO_PWMOD_ARG_PLACEHOLDER_LENGTH.get(),
         INFO_PWMOD_ARG_DESC_GENERATED_PASSWORD_LENGTH.get(), 1,
         Integer.MAX_VALUE, 12);
    generatedPasswordLength.addLongIdentifier("generated-password-length",
         true);
    generatedPasswordLength.addLongIdentifier("generatedPWLength", true);
    generatedPasswordLength.addLongIdentifier("generated-pw-length", true);
    generatedPasswordLength.addLongIdentifier("passwordLength", true);
    generatedPasswordLength.addLongIdentifier("password-length", true);
    generatedPasswordLength.addLongIdentifier("pwLength", true);
    generatedPasswordLength.addLongIdentifier("pw-length", true);
    generatedPasswordLength.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_NEW_PASSWORD.get());
    parser.addArgument(generatedPasswordLength);

    generatedPasswordCharacterSet = new StringArgument(null,
         "generatedPasswordCharacterSet", false, 0,
         INFO_PWMOD_ARG_PLACEHOLDER_CHARS.get(),
         INFO_PWMOD_ARG_DESC_GENERATED_PASSWORD_CHARACTER_SET.get(), null,
         Collections.unmodifiableList(Arrays.asList(
              "abcdefghijmnopqrstuvwxyz", // Note that some letters and
              "ABCDEFGHJLMNPQRSTUVWXYZ",  // digits are missing in an attempt
              "23456789",                 // to avoid ambiguous characters.
              "@#-_=+.")));
    generatedPasswordCharacterSet.addLongIdentifier(
         "generated-password-character-set", true);
    generatedPasswordCharacterSet.addLongIdentifier("generatedPWCharacterSet",
         true);
    generatedPasswordCharacterSet.addLongIdentifier(
         "generated-pw-character-set", true);
    generatedPasswordCharacterSet.addLongIdentifier("generatedPasswordCharSet",
         true);
    generatedPasswordCharacterSet.addLongIdentifier(
         "generated-password-char-set", true);
    generatedPasswordCharacterSet.addLongIdentifier(
         "generated-password-charset", true);
    generatedPasswordCharacterSet.addLongIdentifier("generatedPWCharSet", true);
    generatedPasswordCharacterSet.addLongIdentifier("generated-pw-char-set",
         true);
    generatedPasswordCharacterSet.addLongIdentifier("generated-pw-charset",
         true);
    generatedPasswordCharacterSet.addLongIdentifier(
         "generatedPasswordCharacters", true);
    generatedPasswordCharacterSet.addLongIdentifier(
         "generated-password-characters", true);
    generatedPasswordCharacterSet.addLongIdentifier("generatedPWCharacters",
         true);
    generatedPasswordCharacterSet.addLongIdentifier("generated-pw-characters",
         true);
    generatedPasswordCharacterSet.addLongIdentifier("generatedPasswordChars",
         true);
    generatedPasswordCharacterSet.addLongIdentifier("generated-password-chars",
         true);
    generatedPasswordCharacterSet.addLongIdentifier("generatedPWChars", true);
    generatedPasswordCharacterSet.addLongIdentifier("generated-pw-chars", true);
    generatedPasswordCharacterSet.addLongIdentifier("passwordCharacters", true);
    generatedPasswordCharacterSet.addLongIdentifier("password-characters",
         true);
    generatedPasswordCharacterSet.addLongIdentifier("pwCharacters", true);
    generatedPasswordCharacterSet.addLongIdentifier("pw-characters", true);
    generatedPasswordCharacterSet.addLongIdentifier("passwordCharacterSet",
         true);
    generatedPasswordCharacterSet.addLongIdentifier("password-character-set",
         true);
    generatedPasswordCharacterSet.addLongIdentifier("pwCharacterSet", true);
    generatedPasswordCharacterSet.addLongIdentifier("pw-character-set", true);
    generatedPasswordCharacterSet.addLongIdentifier("passwordCharSet", true);
    generatedPasswordCharacterSet.addLongIdentifier("password-charset", true);
    generatedPasswordCharacterSet.addLongIdentifier("password-char-set", true);
    generatedPasswordCharacterSet.addLongIdentifier("pwCharSet", true);
    generatedPasswordCharacterSet.addLongIdentifier("pw-charset", true);
    generatedPasswordCharacterSet.addLongIdentifier("pw-char-set", true);
    generatedPasswordCharacterSet.addLongIdentifier("passwordChars", true);
    generatedPasswordCharacterSet.addLongIdentifier("password-chars", true);
    generatedPasswordCharacterSet.addLongIdentifier("pw-chars", true);
    generatedPasswordCharacterSet.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_NEW_PASSWORD.get());
    parser.addArgument(generatedPasswordCharacterSet);


    // Current password arguments.
    currentPassword = new StringArgument('c', "currentPassword", false, 1,
         INFO_PWMOD_ARG_PLACEHOLDER_PASSWORD.get(),
         INFO_PWMOD_ARG_DESC_CURRENT_PASSWORD.get());
    currentPassword.addLongIdentifier("current-password", true);
    currentPassword.addLongIdentifier("currentPW", true);
    currentPassword.addLongIdentifier("current-pw", true);
    currentPassword.addLongIdentifier("current", true);
    currentPassword.addLongIdentifier("oldPassword", true);
    currentPassword.addLongIdentifier("old-password", true);
    currentPassword.addLongIdentifier("oldPW", true);
    currentPassword.addLongIdentifier("old-pw", true);
    currentPassword.addLongIdentifier("old", true);
    currentPassword.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_CURRENT_PASSWORD.get());
    parser.addArgument(currentPassword);

    currentPasswordFile = new FileArgument('C', "currentPasswordFile", false, 1,
         null, INFO_PWMOD_ARG_DESC_CURRENT_PASSWORD_FILE.get(), true, true,
         true, false);
    currentPasswordFile.addLongIdentifier("current-password-file", true);
    currentPasswordFile.addLongIdentifier("currentPWFile", true);
    currentPasswordFile.addLongIdentifier("current-pw-file", true);
    currentPasswordFile.addLongIdentifier("currentFile", true);
    currentPasswordFile.addLongIdentifier("current-file", true);
    currentPasswordFile.addLongIdentifier("currentPasswordPath", true);
    currentPasswordFile.addLongIdentifier("current-password-path", true);
    currentPasswordFile.addLongIdentifier("currentPWPath", true);
    currentPasswordFile.addLongIdentifier("current-pw-path", true);
    currentPasswordFile.addLongIdentifier("currentPath", true);
    currentPasswordFile.addLongIdentifier("current-path", true);
    currentPasswordFile.addLongIdentifier("oldPasswordFile", true);
    currentPasswordFile.addLongIdentifier("old-password-file", true);
    currentPasswordFile.addLongIdentifier("oldPWFile", true);
    currentPasswordFile.addLongIdentifier("old-pw-file", true);
    currentPasswordFile.addLongIdentifier("oldFile", true);
    currentPasswordFile.addLongIdentifier("old-file", true);
    currentPasswordFile.addLongIdentifier("oldPasswordPath", true);
    currentPasswordFile.addLongIdentifier("old-password-path", true);
    currentPasswordFile.addLongIdentifier("oldPWPath", true);
    currentPasswordFile.addLongIdentifier("old-pw-path", true);
    currentPasswordFile.addLongIdentifier("oldPath", true);
    currentPasswordFile.addLongIdentifier("old-path", true);
    currentPasswordFile.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_CURRENT_PASSWORD.get());
    parser.addArgument(currentPasswordFile);

    promptForCurrentPassword = new BooleanArgument(null,
         "promptForCurrentPassword", 1,
         INFO_PWMOD_ARG_DESC_PROMPT_FOR_CURRENT_PASSWORD.get());
    promptForCurrentPassword.addLongIdentifier("prompt-for-current-password",
         true);
    promptForCurrentPassword.addLongIdentifier("promptForCurrentPW", true);
    promptForCurrentPassword.addLongIdentifier("prompt-for-current-pw", true);
    promptForCurrentPassword.addLongIdentifier("promptForCurrent", true);
    promptForCurrentPassword.addLongIdentifier("prompt-for-current", true);
    promptForCurrentPassword.addLongIdentifier("promptCurrent", true);
    promptForCurrentPassword.addLongIdentifier("prompt-current", true);
    promptForCurrentPassword.addLongIdentifier("promptForOldPassword", true);
    promptForCurrentPassword.addLongIdentifier("prompt-for-old-password", true);
    promptForCurrentPassword.addLongIdentifier("promptForOldPW", true);
    promptForCurrentPassword.addLongIdentifier("prompt-for-old-pw", true);
    promptForCurrentPassword.addLongIdentifier("promptForOld", true);
    promptForCurrentPassword.addLongIdentifier("prompt-for-old", true);
    promptForCurrentPassword.addLongIdentifier("promptOld", true);
    promptForCurrentPassword.addLongIdentifier("prompt-old", true);
    promptForCurrentPassword.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_CURRENT_PASSWORD.get());
    parser.addArgument(promptForCurrentPassword);


    // Bind control arguments.
    bindControl = new ControlArgument(null, "bindControl", false, 0, null,
         INFO_PWMOD_ARG_DESC_BIND_CONTROL.get());
    bindControl.addLongIdentifier("bind-control", true);
    bindControl.setArgumentGroupName(INFO_PWMOD_ARG_GROUP_BIND_CONTROL.get());
    parser.addArgument(bindControl);

    useAuthorizationIdentityControl = new BooleanArgument(null,
         "useAuthorizationIdentityControl", 1,
         INFO_PWMOD_ARG_DESC_USE_AUTHZ_ID_CONTROL.get());
    useAuthorizationIdentityControl.addLongIdentifier(
         "use-authorization-identity-control", true);
    useAuthorizationIdentityControl.addLongIdentifier(
         "useAuthorizationID-control", true);
    useAuthorizationIdentityControl.addLongIdentifier(
         "use-authorization-id-control", true);
    useAuthorizationIdentityControl.addLongIdentifier(
         "authorizationIdentityControl", true);
    useAuthorizationIdentityControl.addLongIdentifier(
         "authorization-identity-control", true);
    useAuthorizationIdentityControl.addLongIdentifier("authorizationIDControl",
         true);
    useAuthorizationIdentityControl.addLongIdentifier(
         "authorization-id-control", true);
    useAuthorizationIdentityControl.addLongIdentifier("authzIDControl", true);
    useAuthorizationIdentityControl.addLongIdentifier("authz-id-control", true);
    useAuthorizationIdentityControl.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_BIND_CONTROL.get());
    parser.addArgument(useAuthorizationIdentityControl);

    usePasswordPolicyControlOnBind = new BooleanArgument(null,
         "usePasswordPolicyControlOnBind", 1,
         INFO_PWMOD_ARG_DESC_USE_PW_POLICY_CONTROL_ON_BIND.get());
    usePasswordPolicyControlOnBind.addLongIdentifier(
         "use-password-policy-control-on-bind", true);
    usePasswordPolicyControlOnBind.addLongIdentifier("usePWPolicyControlOnBind",
         true);
    usePasswordPolicyControlOnBind.addLongIdentifier(
         "use-pw-policy-control-on-bind", true);
    usePasswordPolicyControlOnBind.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_BIND_CONTROL.get());
    parser.addArgument(usePasswordPolicyControlOnBind);

    getAuthorizationEntryAttribute = new StringArgument(null,
         "getAuthorizationEntryAttribute", false, 0,
         INFO_PWMOD_ARG_PLACEHOLDER_ATTRIBUTE_NAME.get(),
         INFO_PWMOD_ARG_DESC_GET_AUTHZ_ENTRY_ATTRIBUTE.get());
    getAuthorizationEntryAttribute.addLongIdentifier(
         "get-authorization-entry-attribute", true);
    getAuthorizationEntryAttribute.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_BIND_CONTROL.get());
    parser.addArgument(getAuthorizationEntryAttribute);

    getUserResourceLimits = new BooleanArgument(null, "getUserResourceLimits",
         1, INFO_PWMOD_ARG_DESC_GET_USER_RESOURCE_LIMITS.get());
    getUserResourceLimits.addLongIdentifier("get-user-resource-limits", true);
    getUserResourceLimits.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_BIND_CONTROL.get());
    parser.addArgument(getUserResourceLimits);


    // Update control arguments.
    updateControl = new ControlArgument('J', "updateControl", false, 0, null,
         INFO_PWMOD_ARG_DESC_UPDATE_CONTROL.get());
    updateControl.addLongIdentifier("update-control", true);
    updateControl.addLongIdentifier("control", true);
    updateControl.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(updateControl);

    usePasswordPolicyControlOnUpdate = new BooleanArgument(null,
         "usePasswordPolicyControlOnUpdate", 1,
         INFO_PWMOD_ARG_DESC_USE_PW_POLICY_CONTROL_ON_UPDATE.get());
    usePasswordPolicyControlOnUpdate.addLongIdentifier(
         "use-password-policy-control-on-update", true);
    usePasswordPolicyControlOnUpdate.addLongIdentifier(
         "usePWPolicyControlOnUpdate", true);
    usePasswordPolicyControlOnUpdate.addLongIdentifier(
         "use-pw-policy-control-on-update", true);
    usePasswordPolicyControlOnUpdate.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(usePasswordPolicyControlOnUpdate);

    noOperation = new BooleanArgument(null, "noOperation", 1,
         INFO_PWMOD_ARG_DESC_NO_OPERATION.get());
    noOperation.addLongIdentifier("no-operation", true);
    noOperation.addLongIdentifier("noOp", true);
    noOperation.addLongIdentifier("no-op", true);
    noOperation.setArgumentGroupName(INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(noOperation);

    getPasswordValidationDetails = new BooleanArgument(null,
         "getPasswordValidationDetails", 1,
         INFO_PWMOD_ARG_DESC_GET_PW_VALIDATION_DETAILS.get());
    getPasswordValidationDetails.addLongIdentifier(
         "get-password-validation-details", true);
    getPasswordValidationDetails.addLongIdentifier("getPWValidationDetails",
         true);
    getPasswordValidationDetails.addLongIdentifier("get-pw-validation-details",
         true);
    getPasswordValidationDetails.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(getPasswordValidationDetails);

    retireCurrentPassword = new BooleanArgument(null, "retireCurrentPassword",
         1, INFO_PWMOD_ARG_DESC_RETIRE_CURRENT_PASSWORD.get());
    retireCurrentPassword.addLongIdentifier("retire-current-password", true);
    retireCurrentPassword.addLongIdentifier("retireCurrentPW", true);
    retireCurrentPassword.addLongIdentifier("retire-current-pw", true);
    retireCurrentPassword.addLongIdentifier("retirePassword", true);
    retireCurrentPassword.addLongIdentifier("retire-password", true);
    retireCurrentPassword.addLongIdentifier("retirePW", true);
    retireCurrentPassword.addLongIdentifier("retire-pw", true);
    retireCurrentPassword.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(retireCurrentPassword);

    purgeCurrentPassword = new BooleanArgument(null, "purgeCurrentPassword", 1,
         INFO_PWMOD_ARG_DESC_PURGE_CURRENT_PASSWORD.get());
    purgeCurrentPassword.addLongIdentifier("purge-current-password", true);
    purgeCurrentPassword.addLongIdentifier("purgeCurrentPW", true);
    purgeCurrentPassword.addLongIdentifier("purge-current-pw", true);
    purgeCurrentPassword.addLongIdentifier("purgePassword", true);
    purgeCurrentPassword.addLongIdentifier("purge-password", true);
    purgeCurrentPassword.addLongIdentifier("purgePW", true);
    purgeCurrentPassword.addLongIdentifier("purge-pw", true);
    purgeCurrentPassword.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(purgeCurrentPassword);

    passwordUpdateBehavior = new StringArgument(null,
         "passwordUpdateBehavior", false, 0,
         INFO_PWMOD_ARG_PLACEHOLDER_NAME_VALUE.get(),
         INFO_PWMOD_ARG_DESC_PASSWORD_UPDATE_BEHAVIOR.get());
    passwordUpdateBehavior.addLongIdentifier("password-update-behavior", true);
    passwordUpdateBehavior.addLongIdentifier("pwUpdateBehavior", true);
    passwordUpdateBehavior.addLongIdentifier("pw-update-behavior", true);
    passwordUpdateBehavior.addLongIdentifier("updateBehavior", true);
    passwordUpdateBehavior.addLongIdentifier("update-behavior", true);
    passwordUpdateBehavior.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(passwordUpdateBehavior);

    useAssuredReplication = new BooleanArgument(null, "useAssuredReplication",
         1, INFO_PWMOD_ARG_DESC_ASSURED_REPLICATION.get());
    useAssuredReplication.addLongIdentifier("use-assured-replication", true);
    useAssuredReplication.addLongIdentifier("assuredReplication", true);
    useAssuredReplication.addLongIdentifier("assured-replication", true);
    useAssuredReplication.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(useAssuredReplication);

    assuredReplicationLocalLevel = new StringArgument(null,
         "assuredReplicationLocalLevel", false, 1,
         INFO_PWMOD_ARG_PLACEHOLDER_LEVEL.get(),
         INFO_PWMOD_ARG_DESC_ASSURED_REPLICATION_LOCAL_LEVEL.get(),
         StaticUtils.setOf(
              ASSURED_REPLICATION_LOCAL_LEVEL_NONE,
              ASSURED_REPLICATION_LOCAL_LEVEL_RECEIVED_ANY_SERVER,
              ASSURED_REPLICATION_LOCAL_LEVEL_PROCESSED_ALL_SERVERS));
    assuredReplicationLocalLevel.addLongIdentifier(
         "assured-replication-local-level", true);
    assuredReplicationLocalLevel.addLongIdentifier("localLevel", true);
    assuredReplicationLocalLevel.addLongIdentifier("local-level", true);
    assuredReplicationLocalLevel.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(assuredReplicationLocalLevel);

    assuredReplicationRemoteLevel = new StringArgument(null,
         "assuredReplicationRemoteLevel", false, 1,
         INFO_PWMOD_ARG_PLACEHOLDER_LEVEL.get(),
         INFO_PWMOD_ARG_DESC_ASSURED_REPLICATION_REMOTE_LEVEL.get(),
         StaticUtils.setOf(
              ASSURED_REPLICATION_REMOTE_LEVEL_NONE,
              ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ANY_REMOTE_LOCATION,
              ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ALL_REMOTE_LOCATIONS,
              ASSURED_REPLICATION_REMOTE_LEVEL_PROCESSED_ALL_REMOTE_SERVERS));
    assuredReplicationRemoteLevel.addLongIdentifier(
         "assured-replication-remote-level", true);
    assuredReplicationRemoteLevel.addLongIdentifier("remoteLevel", true);
    assuredReplicationRemoteLevel.addLongIdentifier("remote-level", true);
    assuredReplicationRemoteLevel.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(assuredReplicationRemoteLevel);

    assuredReplicationTimeout = new DurationArgument(null,
         "assuredReplicationTimeout", false,
         INFO_PWMOD_ARG_PLACEHOLDER_TIMEOUT.get(),
         INFO_PWMOD_ARG_DESC_ASSURED_REPLICATION_TIMEOUT.get());
    assuredReplicationTimeout.addLongIdentifier("assured-replication-timeout",
         true);
    assuredReplicationTimeout.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(assuredReplicationTimeout);

    operationPurpose = new StringArgument(null, "operationPurpose", false, 1,
         INFO_PWMOD_ARG_PLACEHOLDER_PURPOSE.get(),
         INFO_PWMOD_ARG_DESC_OPERATION_PURPOSE.get());
    operationPurpose.addLongIdentifier("operation-purpose", true);
    operationPurpose.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_UPDATE_CONTROL.get());
    parser.addArgument(operationPurpose);


    // Other arguments
    passwordAttribute = new StringArgument(null, "passwordAttribute", false, 1,
         INFO_PWMOD_ARG_PLACEHOLDER_ATTRIBUTE_NAME.get(),
         INFO_PWMOD_ARG_DESC_PASSWORD_ATTRIBUTE.get(),
         DEFAULT_PASSWORD_ATTRIBUTE);
    passwordAttribute.addLongIdentifier("password-attribute", true);
    passwordAttribute.addLongIdentifier("passwordAttr", true);
    passwordAttribute.addLongIdentifier("password-attr", true);
    passwordAttribute.addLongIdentifier("pwAttribute", true);
    passwordAttribute.addLongIdentifier("pw-attribute", true);
    passwordAttribute.addLongIdentifier("pwAttr", true);
    passwordAttribute.addLongIdentifier("pw-attr", true);
    passwordAttribute.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_OTHER.get());

    passwordChangeMethod = new StringArgument(null, "passwordChangeMethod",
         false, 1, INFO_PWMOD_ARG_PLACEHOLDER_CHANGE_METHOD.get(),
         INFO_PWMOD_ARG_DESC_PASSWORD_CHANGE_METHOD.get(),
         StaticUtils.setOf(
              PASSWORD_CHANGE_METHOD_PW_MOD_EXTOP,
              PASSWORD_CHANGE_METHOD_LDAP_MOD,
              PASSWORD_CHANGE_METHOD_AD));
    passwordChangeMethod.addLongIdentifier("password-change-method", true);
    passwordChangeMethod.addLongIdentifier("pwChangeMethod", true);
    passwordChangeMethod.addLongIdentifier("pw-change-method", true);
    passwordChangeMethod.addLongIdentifier("changeMethod", true);
    passwordChangeMethod.addLongIdentifier("change-method", true);
    passwordChangeMethod.addLongIdentifier("method", true);
    passwordChangeMethod.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_OTHER.get());
    parser.addArgument(passwordChangeMethod);

    followReferrals = new BooleanArgument(null, "followReferrals", 1,
         INFO_PWMOD_ARG_DESC_FOLLOW_REFERRALS.get());
    followReferrals.addLongIdentifier("follow-referrals", true);
    followReferrals.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_OTHER.get());
    parser.addArgument(followReferrals);

    useAdministrativeSession = new BooleanArgument(null,
         "useAdministrativeSession", 1,
         INFO_PWMOD_ARG_DESC_USE_ADMIN_SESSION.get());
    useAdministrativeSession.addLongIdentifier("use-administrative-session",
         true);
    useAdministrativeSession.addLongIdentifier("useAdminSession", true);
    useAdministrativeSession.addLongIdentifier("use-admin-session", true);
    useAdministrativeSession.addLongIdentifier("administrativeSession", true);
    useAdministrativeSession.addLongIdentifier("administrative-session", true);
    useAdministrativeSession.addLongIdentifier("adminSession", true);
    useAdministrativeSession.addLongIdentifier("admin-session", true);
    useAdministrativeSession.setArgumentGroupName(
         INFO_PWMOD_ARG_GROUP_OTHER.get());
    parser.addArgument(useAdministrativeSession);

    verbose = new BooleanArgument('v', "verbose", 1,
         INFO_PWMOD_ARG_DESC_VERBOSE.get());
    verbose.setArgumentGroupName(INFO_PWMOD_ARG_GROUP_OTHER.get());
    parser.addArgument(verbose);

    // This argument isn't actually used, but provides command-line backward
    // compatibility with an existing implementation.
    scriptFriendly = new BooleanArgument(null, "script-friendly", 1,
         INFO_PWMOD_ARG_DESC_SCRIPT_FRIENDLY.get());
    scriptFriendly.setArgumentGroupName(INFO_PWMOD_ARG_GROUP_OTHER.get());
    scriptFriendly.setHidden(true);
    parser.addArgument(scriptFriendly);


    // Argument constraints.
    parser.addExclusiveArgumentSet(userIdentity, provideBindDNAsUserIdentity);

    final DNArgument bindDNArgument =
         parser.getDNArgument(BIND_DN_ARGUMENT_LONG_IDENTIFIER);
    parser.addDependentArgumentSet(provideBindDNAsUserIdentity, bindDNArgument);

    parser.addExclusiveArgumentSet(newPassword, newPasswordFile,
         promptForNewPassword, generateClientSideNewPassword);

    parser.addDependentArgumentSet(generatedPasswordLength,
         generateClientSideNewPassword);
    parser.addDependentArgumentSet(generatedPasswordCharacterSet,
         generateClientSideNewPassword);

    parser.addExclusiveArgumentSet(currentPassword, currentPasswordFile,
         promptForCurrentPassword);

    parser.addDependentArgumentSet(assuredReplicationLocalLevel,
         useAssuredReplication);
    parser.addDependentArgumentSet(assuredReplicationRemoteLevel,
         useAssuredReplication);
    parser.addDependentArgumentSet(assuredReplicationTimeout,
         useAssuredReplication);

    parser.addExclusiveArgumentSet(retireCurrentPassword, purgeCurrentPassword);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected Set<Character> getSuppressedShortIdentifiers()
  {
    return StaticUtils.setOf('N');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedNonLDAPArgumentValidation()
         throws ArgumentException
  {
    // Make sure that if any generate password character sets were provided,
    // they must all be non-empty.
    if (generatedPasswordCharacterSet.isPresent())
    {
      for (final String charSet : generatedPasswordCharacterSet.getValues())
      {
        if (charSet.isEmpty())
        {
          throw new ArgumentException(ERR_PWMOD_CHAR_SET_EMPTY.get(
               generatedPasswordCharacterSet.getIdentifierString()));
        }
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    LDAPConnectionPool pool = null;
    try
    {
      // Create a connection pool that will be used to communicate with the
      // directory server.  If we should use an administrative session, then
      // create a connect processor that will be used to start the session
      // before performing the bind.
      try
      {
        final StartAdministrativeSessionPostConnectProcessor p;
        if (useAdministrativeSession.isPresent())
        {
          p = new StartAdministrativeSessionPostConnectProcessor(
               new StartAdministrativeSessionExtendedRequest(getToolName(),
                    true));
        }
        else
        {
          p = null;
        }

        pool = getConnectionPool(1, 2, 0, p, null, true,
             new ReportBindResultLDAPConnectionPoolHealthCheck(this, true,
                  verbose.isPresent()));


        // Figure out the method to use to update the password.
        final String updateMethod;
        try
        {
          updateMethod = getPasswordUpdateMethod(pool);
        }
        catch (final LDAPException e)
        {
          Debug.debugException(e);
          logCompletionMessage(true, e.getMessage());
          return e.getResultCode();
        }


        switch (updateMethod)
        {
          case PASSWORD_CHANGE_METHOD_PW_MOD_EXTOP:
            return doPasswordModifyExtendedOperation(pool);

          case PASSWORD_CHANGE_METHOD_AD:
            return doLDAPModifyPasswordUpdate(pool, true);

          case PASSWORD_CHANGE_METHOD_LDAP_MOD:
          default:
            return doLDAPModifyPasswordUpdate(pool, false);
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        // Unable to create the connection pool, which means that either the
        // connection could not be established or the attempt to authenticate
        // the connection failed.  If the bind failed, then the report bind
        // result health check should have already reported the bind failure.
        // If the failure was something else, then display that failure result.
        if (le.getResultCode() != ResultCode.INVALID_CREDENTIALS)
        {
          for (final String line :
               ResultUtils.formatResult(le, true, 0, WRAP_COLUMN))
          {
            err(line);
          }
        }
        return le.getResultCode();
      }
    }
    finally
    {
      if (pool != null)
      {
        pool.close();
      }
    }
  }



  /**
   * Determines the method that should be used to update the password.
   *
   * @param  pool  The connection pool to use to communicate with the
   *               directory server, if appropriate.
   *
   * @return  The method that should be used to update the password.  The value
   *          returned will be one of
   *          {@link #PASSWORD_CHANGE_METHOD_PW_MOD_EXTOP},
   *          {@link #PASSWORD_CHANGE_METHOD_LDAP_MOD}, or
   *          {@link #PASSWORD_CHANGE_METHOD_AD}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to make the
   *                         determination.
   */
  @NotNull()
  private String getPasswordUpdateMethod(@NotNull final LDAPConnectionPool pool)
          throws LDAPException
  {
    if (passwordChangeMethod.isPresent())
    {
      switch (StaticUtils.toLowerCase(passwordChangeMethod.getValue()))
      {
        case PASSWORD_CHANGE_METHOD_PW_MOD_EXTOP:
          return PASSWORD_CHANGE_METHOD_PW_MOD_EXTOP;
        case PASSWORD_CHANGE_METHOD_LDAP_MOD:
          return PASSWORD_CHANGE_METHOD_LDAP_MOD;
        case PASSWORD_CHANGE_METHOD_AD:
          return PASSWORD_CHANGE_METHOD_AD;
      }
    }


    // Retrieve the root DSE from the directory server.  If we can't get the
    // root DSE, then default to the password modify extended operation.
    final RootDSE rootDSE;
    try
    {
      rootDSE = pool.getRootDSE();
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      return PASSWORD_CHANGE_METHOD_PW_MOD_EXTOP;
    }

    if (rootDSE == null)
    {
      return PASSWORD_CHANGE_METHOD_PW_MOD_EXTOP;
    }


    // If the root DSE claims support for the password modify extended
    // operation, then use that method.
    if (rootDSE.supportsExtendedOperation(
         PasswordModifyExtendedRequest.PASSWORD_MODIFY_REQUEST_OID))
    {
      if (verbose.isPresent())
      {
        wrapOut(0, WRAP_COLUMN,
             INFO_PWMOD_SELECTING_PW_MOD_EXTOP_METHOD.get());
      }

      return PASSWORD_CHANGE_METHOD_PW_MOD_EXTOP;
    }


    // We need to differentiate between Active Directory and other types of
    // servers.  Unfortunately, Active Directory doesn't seem to provide
    // vendorName or vendorVersion attributes in its root DSE, so we'll need to
    // use some other means of detecting it.  Let's assume that if the server
    // advertises support for at least twenty supported controls in Microsoft's
    // OID range (starting with 1.2.840.113556), then it's an Active Directory
    // instance.  At the time this was written, two different AD versions each
    // advertised support for nearly double that number.
    int numMicrosoftControlsSupported = 0;
    for (final String oid : rootDSE.getSupportedControlOIDs())
    {
      if (oid.startsWith(MICROSOFT_BASE_OBJECT_IDENTIFIER + '.'))
      {
        numMicrosoftControlsSupported++;
      }
    }

    if (numMicrosoftControlsSupported >= 20)
    {
      if (verbose.isPresent())
      {
        wrapOut(0, WRAP_COLUMN,
             INFO_PWMOD_SELECTING_AD_METHOD_CONTROL_COUNT.get(
                  numMicrosoftControlsSupported,
                  MICROSOFT_BASE_OBJECT_IDENTIFIER));
      }

      return PASSWORD_CHANGE_METHOD_AD;
    }


    // Fall back to a default of a regular LDAP modify operation.
    if (verbose.isPresent())
    {
      wrapOut(0, WRAP_COLUMN,
           INFO_PWMOD_DEFAULTING_TO_LDAP_MOD.get());
    }

    return PASSWORD_CHANGE_METHOD_LDAP_MOD;
  }



  /**
   * Attempts a password modify extended operation to change the target user's
   * password.
   *
   * @param  pool  A connection pool to use to communicate with the directory
   *               server.
   *
   * @return  A result code that indicates whether the password update was
   *          successful.
   */
  @NotNull()
  private ResultCode doPasswordModifyExtendedOperation(
                          @NotNull final LDAPConnectionPool pool)
  {
    // Create the password modify extended request to be processed.
    final String identity;
    final byte[] currentPW;
    final byte[] newPW;
    final Control[] controls;
    try
    {
      identity = getUserIdentity(null, false);
      currentPW = getCurrentPassword();
      newPW = getNewPassword();
      controls = getUpdateControls();
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true, e.getMessage());
      return e.getResultCode();
    }

    final PasswordModifyExtendedRequest passwordModifyRequest =
         new PasswordModifyExtendedRequest(identity, currentPW, newPW,
              controls);


    // Send the request and interpret the response, including special handling
    // for any referral that might have been returned.
    LDAPConnection connection = null;
    try
    {
      connection = pool.getConnection();
      final PasswordModifyExtendedResult passwordModifyResult =
           (PasswordModifyExtendedResult)
           connection.processExtendedOperation(passwordModifyRequest);

      out();
      out(INFO_PWMOD_EXTOP_RESULT_HEADER.get());
      for (final String line :
           ResultUtils.formatResult(passwordModifyResult, true, 0, WRAP_COLUMN))
      {
        out(line);
      }
      out();

      final String generatedPassword =
           passwordModifyResult.getGeneratedPassword();
      if (passwordModifyResult.getResultCode() == ResultCode.SUCCESS)
      {
        logCompletionMessage(false, INFO_PWMOD_EXTOP_SUCCESSFUL.get());
        if (generatedPassword != null)
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_PWMOD_SERVER_GENERATED_PW.get(generatedPassword));
        }

        return ResultCode.SUCCESS;
      }
      else if (passwordModifyResult.getResultCode() == ResultCode.NO_OPERATION)
      {
        logCompletionMessage(false, INFO_PWMOD_EXTOP_NO_OP.get());
        if (generatedPassword != null)
        {
          out();
          wrapOut(0, WRAP_COLUMN,
               INFO_PWMOD_SERVER_GENERATED_PW.get(generatedPassword));
        }

        return ResultCode.SUCCESS;
      }
      else if ((passwordModifyResult.getResultCode() == ResultCode.REFERRAL) &&
           followReferrals.isPresent() &&
           (passwordModifyResult.getReferralURLs().length > 0))
      {
        // The LDAP SDK doesn't support automatic referral following for
        // extended operations.  If appropriate, try to follow it ourselves.
        return followPasswordModifyReferral(passwordModifyRequest,
             passwordModifyResult, connection, 1);
      }
      else
      {
        logCompletionMessage(true,
             ERR_PWMOD_EXTOP_FAILED.get(
                  String.valueOf(passwordModifyResult.getResultCode()),
                  passwordModifyResult.getDiagnosticMessage()));
        return passwordModifyResult.getResultCode();
      }
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);

      err();
      err(INFO_PWMOD_EXTOP_RESULT_HEADER.get());
      for (final String line :
           ResultUtils.formatResult(e, true, 0, WRAP_COLUMN))
      {
        err(line);
      }
      err();

      if (connection != null)
      {
        pool.releaseDefunctConnection(connection);
        connection = null;
      }

      logCompletionMessage(true,
           ERR_PWMOD_EXTOP_ERROR.get(String.valueOf(e.getResultCode()),
                e.getMessage()));
      return e.getResultCode();
    }
    finally
    {
      if (connection != null)
      {
        pool.releaseConnection(connection);
      }
    }
  }



  /**
   * Attempts to follow a referral that was returned in response to a password
   * modify extended request.
   *
   * @param  request               The extended request that was sent.
   * @param  result                The extended result that was received,
   *                               including the referral details.
   * @param  receivedOnConnection  The LDAP connection on which the referral
   *                               result was received.
   * @param  referralCount         The number of referrals that have been
   *                               returned so far.  If this is too high, then
   *                               subsequent referrals will not be followed.
   *
   * @return  A result code that indicates whether the password update was
   *          successful.
   */
  @NotNull()
  private ResultCode followPasswordModifyReferral(
                          @NotNull final PasswordModifyExtendedRequest request,
                          @NotNull final PasswordModifyExtendedResult result,
                          @NotNull final LDAPConnection receivedOnConnection,
                          final int referralCount)
  {
    final List<LDAPURL> referralURLs = new ArrayList<>();
    for (final String urlString : result.getReferralURLs())
    {
      try
      {
        referralURLs.add(new LDAPURL(urlString));
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
      }
    }

    if (referralURLs.isEmpty())
    {
      logCompletionMessage(true,
           ERR_PWMOD_EXTOP_NO_VALID_REFERRAL_URLS.get(String.valueOf(result)));
      return ResultCode.REFERRAL;
    }

    LDAPException firstException = null;
    for (final LDAPURL url : referralURLs)
    {
      try (LDAPConnection referralConnection =
           receivedOnConnection.getReferralConnection(url,
                receivedOnConnection))
      {
        final String referredUserIdentity;
        if (url.getBaseDN().isNullDN())
        {
          referredUserIdentity = request.getUserIdentity();
        }
        else
        {
          referredUserIdentity = url.getBaseDN().toString();
        }

        final PasswordModifyExtendedRequest referralRequest =
             new PasswordModifyExtendedRequest(referredUserIdentity,
                  request.getOldPassword(), request.getNewPassword(),
                  request.getControls());
        final PasswordModifyExtendedResult referralResult =
             (PasswordModifyExtendedResult)
             referralConnection.processExtendedOperation(referralRequest);

        out();
        out(INFO_PWMOD_EXTOP_RESULT_HEADER.get());
        for (final String line :
             ResultUtils.formatResult(referralResult, true, 0, WRAP_COLUMN))
        {
          out(line);
        }
        out();

        final String generatedPassword = referralResult.getGeneratedPassword();
        if (referralResult.getResultCode() == ResultCode.SUCCESS)
        {
          logCompletionMessage(false, INFO_PWMOD_EXTOP_SUCCESSFUL.get());
          if (generatedPassword != null)
          {
            out();
            wrapOut(0, WRAP_COLUMN,
                 INFO_PWMOD_SERVER_GENERATED_PW.get(generatedPassword));
          }

          return ResultCode.SUCCESS;
        }
        else if (referralResult.getResultCode() == ResultCode.NO_OPERATION)
        {
          logCompletionMessage(false, INFO_PWMOD_EXTOP_NO_OP.get());
          if (generatedPassword != null)
          {
            out();
            wrapOut(0, WRAP_COLUMN,
                 INFO_PWMOD_SERVER_GENERATED_PW.get(generatedPassword));
          }

          return ResultCode.SUCCESS;
        }
        else if (referralResult.getResultCode() == ResultCode.REFERRAL)
        {
          final int maxReferralCount = receivedOnConnection.
               getConnectionOptions().getReferralHopLimit();
          if (referralCount > maxReferralCount)
          {
            logCompletionMessage(true,
                 ERR_PWMOD_TOO_MANY_REFERRALS.get());
            return ResultCode.REFERRAL_LIMIT_EXCEEDED;
          }
          else
          {
            return followPasswordModifyReferral(referralRequest, referralResult,
                 referralConnection, (referralCount + 1));
          }
        }
        else
        {
          if (firstException == null)
          {
            firstException = new LDAPExtendedOperationException(referralResult);
          }
        }
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        if (firstException == null)
        {
          firstException = e;
        }
      }
    }


    logCompletionMessage(true,
         ERR_PWMOD_FOLLOW_REFERRAL_FAILED.get(
              String.valueOf(firstException.getResultCode()),
              firstException.getDiagnosticMessage()));
    return firstException.getResultCode();
  }



  /**
   * Attempts a regular LDAP modify operation to change the target user's
   * password.
   *
   * @param  pool               A connection pool to use to communicate with the
   *                            directory server.
   * @param  isActiveDirectory  Indicates whether the target directory server
   *                            is believed to be an Active Directory instance.
   *
   * @return  A result code that indicates whether the password update was
   *          successful.
   */
  @NotNull()
  private ResultCode doLDAPModifyPasswordUpdate(
               @NotNull final LDAPConnectionPool pool,
               final boolean isActiveDirectory)
  {
    // Get the information to include in the password modify extended request.
    byte[] currentPW;
    byte[] newPW;
    final String identity;
    final Control[] controls;
    try
    {
      identity = getUserIdentity(pool, isActiveDirectory);
      currentPW = getCurrentPassword();
      newPW = getNewPassword();
      controls = getUpdateControls();
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      logCompletionMessage(true, e.getMessage());
      return e.getResultCode();
    }


    // If there is no new password, then fail.
    if (newPW == null)
    {
      logCompletionMessage(true,
           ERR_PWMOD_NO_NEW_PW_FOR_MODIFY.get(newPassword.getIdentifierString(),
                newPasswordFile.getIdentifierString(),
                promptForNewPassword.getIdentifierString(),
                generateClientSideNewPassword.getIdentifierString()));
      return ResultCode.PARAM_ERROR;
    }


    // Determine the name of the attribute to modify.
    final String passwordAttr;
    if (isActiveDirectory)
    {
      passwordAttr = AD_PASSWORD_ATTRIBUTE;
      currentPW = encodePasswordForActiveDirectory(currentPW);
      newPW = encodePasswordForActiveDirectory(newPW);
    }
    else
    {
      passwordAttr = passwordAttribute.getValue();
    }


    // Construct the modify request to send to the server.
    final ModifyRequest modifyRequest;
    if (currentPW == null)
    {
      modifyRequest = new ModifyRequest(identity,
           new Modification(ModificationType.REPLACE, passwordAttr, newPW));
    }
    else
    {
      modifyRequest = new ModifyRequest(identity,
           new Modification(ModificationType.DELETE, passwordAttr, currentPW),
           new Modification(ModificationType.ADD, passwordAttr, newPW));
    }

    modifyRequest.setControls(controls);


    // Send the modify request and read the result.
    LDAPResult modifyResult;
    try
    {
      modifyResult = pool.modify(modifyRequest);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      modifyResult = e.toLDAPResult();
    }


    out();
    out(INFO_PWMOD_MODIFY_RESULT_HEADER.get());
    for (final String line :
         ResultUtils.formatResult(modifyResult, true, 0, WRAP_COLUMN))
    {
      out(line);
    }
    out();

    if (modifyResult.getResultCode() == ResultCode.SUCCESS)
    {
      logCompletionMessage(false, INFO_PWMOD_MODIFY_SUCCESSFUL.get());
      return ResultCode.SUCCESS;
    }
    else if (modifyResult.getResultCode() == ResultCode.NO_OPERATION)
    {
      logCompletionMessage(false, INFO_PWMOD_MODIFY_NO_OP.get());
      return ResultCode.SUCCESS;
    }
    else
    {
      logCompletionMessage(true,
           ERR_PWMOD_MODIFY_FAILED.get(
                String.valueOf(modifyResult.getResultCode()),
                modifyResult.getDiagnosticMessage()));
      return modifyResult.getResultCode();
    }
  }



  /**
   *  Encodes the provided password in the form that is needed when changing a
   *  password in Active Directory.  The password must be surrounded in
   *  quotation marks and encoded as UTF-16 with little-Endian ordering.
   *
   * @param  pw  The password to be encoded.  It may optionally be {@code null}.
   *
   * @return  The encoded password.
   */
  @Nullable()
  static byte[] encodePasswordForActiveDirectory(@Nullable final byte[] pw)
  {
    if (pw == null)
    {
      return null;
    }

    final String quotedPassword = '"' + StaticUtils.toUTF8String(pw) + '"';
    return quotedPassword.getBytes(StandardCharsets.UTF_16LE);
  }



  /**
   * Retrieves the user identity for whom to update the password.
   *
   * @param  pool               A connection pool to use to communicate with the
   *                            directory server, if necessary.  This may be
   *                            {@code null} if only an explicitly provided user
   *                            identity should be used.  If it is
   *                            non-{@code null}, then an attempt will be made
   *                            to infer the correct value, and the value
   *                            returned will be a DN.
   * @param  isActiveDirectory  Indicates whether the target directory server
   *                            is believed to be an Active Directory instance.
   *
   * @return  The user identity for whom to update the password.
   *
   * @throws  LDAPException  If a problem occurs while attempting to obtain the
   *                         user identity.
   */
  @NotNull()
  private String getUserIdentity(@NotNull final LDAPConnectionPool pool,
                                 final boolean isActiveDirectory)
          throws LDAPException
  {
    String identity = null;
    final DNArgument bindDNArgument =
         argumentParser.getDNArgument(BIND_DN_ARGUMENT_LONG_IDENTIFIER);
    if (userIdentity.isPresent())
    {
      identity = userIdentity.getValue();
    }
    else if (provideBindDNAsUserIdentity.isPresent())
    {
      identity = bindDNArgument.getStringValue();
      if ((pool == null) && verbose.isPresent())
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_PWMOD_USING_USER_IDENTITY_FROM_DN_FOR_EXTOP.get(identity));
      }
    }
    else
    {
      if ((pool == null) && verbose.isPresent())
      {
        out();
        wrapOut(0, WRAP_COLUMN,
             INFO_PWMOD_OMITTING_USER_IDENTITY_FROM_EXTOP.get());
      }
    }

    if (pool == null)
    {
      return identity;
    }

    if (identity == null)
    {
      if (bindDNArgument.isPresent())
      {
        final DN bindDN = bindDNArgument.getValue();
        if (! bindDN.isNullDN())
        {
          return bindDN.toString();
        }
      }

      final WhoAmIExtendedRequest whoAmIRequest = new WhoAmIExtendedRequest();
      try
      {
        final WhoAmIExtendedResult whoAmIResult = (WhoAmIExtendedResult)
             pool.processExtendedOperation(whoAmIRequest);
        if (whoAmIResult.getResultCode() == ResultCode.SUCCESS)
        {
          identity = whoAmIResult.getAuthorizationID();
        }
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
      }
    }

    if (identity == null)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_PWMOD_CANNOT_DETERMINE_USER_IDENTITY.get(
                userIdentity.getIdentifierString()));
    }


    final String userDN;
    final String lowerIdentity = StaticUtils.toLowerCase(identity);
    if (lowerIdentity.startsWith("dn:"))
    {
      userDN = identity.substring(3).trim();
    }
    else if (lowerIdentity.startsWith("u:"))
    {
      final String username = identity.substring(2).trim();
      if (username.isEmpty())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_PWMOD_USER_IDENTITY_EMPTY_USERNAME.get(
                  userIdentity.getIdentifierString()));
      }

      userDN = searchForUser(pool, username, isActiveDirectory);
    }
    else
    {
      userDN = identity;
    }

    final DN parsedUserDN;
    try
    {
      parsedUserDN = new DN(userDN);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_PWMOD_USER_IDENTITY_NOT_VALID_DN.get(userDN,
                userIdentity.getIdentifierString()),
           e);
    }

    if (parsedUserDN.isNullDN())
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_PWMOD_USER_IDENTITY_EMPTY_DN.get(
                userIdentity.getIdentifierString()));
    }

    if (verbose.isPresent())
    {
      out();
      INFO_PWMOD_USER_IDENTITY_DN_FOR_MOD.get(userDN);
    }

    return userDN;
  }



  /**
   * Performs a search to determine the DN for the user with the given username.
   *
   * @param  pool               A connection pool to use to communicate with the
   *                            directory server.  It must not be {@code null}.
   * @param  username           The username for the target user.  It must not
   *                            be {@code null}.
   * @param  isActiveDirectory  Indicates whether the target directory server
   *                            is believed to be an Active Directory instance.
   *
   * @return  The DN for the user with the given username.
   *
   * @throws  LDAPException  If a problem occurs while searching for the user,
   *                         or if the search does not match exactly one user.
   */
  @NotNull()
  private String searchForUser(@NotNull final LDAPConnectionPool pool,
                               @NotNull final String username,
                               final boolean isActiveDirectory)
          throws LDAPException
  {
    // Construct the filter to use for the search.
    final List<String> filterAttributeNames;
    if (usernameAttribute.isPresent())
    {
      filterAttributeNames = usernameAttribute.getValues();
    }
    else if (isActiveDirectory)
    {
      filterAttributeNames = AD_USERNAME_ATTRIBUTES;
    }
    else
    {
      filterAttributeNames = DEFAULT_USERNAME_ATTRIBUTES;
    }

    final Filter filter;
    if (filterAttributeNames.size() == 1)
    {
      filter = Filter.createEqualityFilter(filterAttributeNames.get(0),
           username);
    }
    else
    {
      final List<Filter> orComponents =
           new ArrayList<>(filterAttributeNames.size());
      for (final String attrName : filterAttributeNames)
      {
        orComponents.add(Filter.createEqualityFilter(attrName, username));
      }

      filter = Filter.createORFilter(orComponents);
    }


    // Create the search request to use to find the target user entry.
    final SearchRequest searchRequest = new SearchRequest(
         searchBaseDN.getStringValue(), SearchScope.SUB, filter,
         SearchRequest.NO_ATTRIBUTES);
    searchRequest.setSizeLimit(1);

    if (verbose.isPresent())
    {
      out();
      wrapOut(0, WRAP_COLUMN,
           INFO_PWMOD_ISSUING_SEARCH_FOR_USER.get(
                String.valueOf(searchRequest), username));
    }


    // Issue the search and get the results.
    SearchResult searchResult;
    LDAPException searchException = null;
    try
    {
      searchResult = pool.search(searchRequest);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      searchException = e;
      searchResult = new SearchResult(e);
    }

    if (verbose.isPresent())
    {
      out();
      for (final String line :
           ResultUtils.formatResult(searchResult, true, 0, WRAP_COLUMN))
      {
        out(line);
      }
    }

    if (searchResult.getResultCode() == ResultCode.SUCCESS)
    {
      if (searchResult.getEntryCount() == 1)
      {
        return searchResult.getSearchEntries().get(0).getDN();
      }
      else
      {
        throw new LDAPException(ResultCode.NO_RESULTS_RETURNED,
             ERR_PWMOD_SEARCH_FOR_USER_NO_MATCHES.get(username));
      }
    }
    else if (searchResult.getResultCode() == ResultCode.SIZE_LIMIT_EXCEEDED)
    {
      throw new LDAPException(ResultCode.SIZE_LIMIT_EXCEEDED,
           ERR_PWMOD_SEARCH_FOR_USER_MULTIPLE_MATCHES.get(username),
           searchException);
    }
    else
    {
      throw new LDAPException(searchResult.getResultCode(),
           ERR_PWMOD_SEARCH_FOR_USER_FAILED.get(username,
                String.valueOf(searchResult.getResultCode()),
                searchResult.getDiagnosticMessage()),
           searchException);
    }
  }



  /**
   * Retrieves the bytes that comprise the current password for the user, if one
   * should be provided in the password update request.
   *
   * @return  The bytes that comprise the current password for the user, or
   *          {@code null} if none should be provided in the password update
   *          request.
   *
   * @throws  LDAPException  If a problem occurs while trying to obtain the
   *                         current password.
   */
  @Nullable()
  private byte[] getCurrentPassword()
          throws LDAPException
  {
    if (currentPassword.isPresent())
    {
      return StaticUtils.getBytes(currentPassword.getValue());
    }
    else if (currentPasswordFile.isPresent())
    {
      final File f = currentPasswordFile.getValue();
      try
      {
        final char[] currentPasswordChars =
             getPasswordFileReader().readPassword(f);
        return StaticUtils.getBytes(new String(currentPasswordChars));
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw new LDAPException(e.getResultCode(),
             ERR_PWMOD_CANNOT_READ_CURRENT_PW_FILE.get(f.getAbsolutePath(),
                  e.getMessage()),
             e);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_PWMOD_CANNOT_READ_CURRENT_PW_FILE.get(f.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    else if (promptForCurrentPassword.isPresent())
    {
      while (true)
      {
        getOut().print(INFO_PWMOD_PROMPT_CURRENT_PW.get());
        try
        {
          final byte[] pwBytes = PasswordReader.readPassword();
          if ((pwBytes == null) || (pwBytes.length == 0))
          {
            err();
            wrapErr(0, WRAP_COLUMN, ERR_PWMOD_PW_EMPTY.get());
            err();
            continue;
          }

          return pwBytes;
        }
        catch (final Exception e)
        {
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_PWMOD_CANNOT_PROMPT_FOR_CURRENT_PW.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves the bytes that comprise the new password for the user, if one
   * should be provided in the password update request.
   *
   * @return  The bytes that comprise the new password for the user, or
   *          {@code null} if none should be provided in the password update
   *          request.
   *
   * @throws  LDAPException  If a problem occurs while trying to obtain the new
   *                         password.
   */
  @Nullable()
  private byte[] getNewPassword()
          throws LDAPException
  {
    if (newPassword.isPresent())
    {
      return StaticUtils.getBytes(newPassword.getValue());
    }
    else if (newPasswordFile.isPresent())
    {
      final File f = newPasswordFile.getValue();
      try
      {
        final char[] newPasswordChars = getPasswordFileReader().readPassword(f);
        return StaticUtils.getBytes(new String(newPasswordChars));
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        throw new LDAPException(e.getResultCode(),
             ERR_PWMOD_CANNOT_READ_NEW_PW_FILE.get(f.getAbsolutePath(),
                  e.getMessage()),
             e);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_PWMOD_CANNOT_READ_NEW_PW_FILE.get(f.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    else if (promptForNewPassword.isPresent())
    {
      while (true)
      {
        getOut().print(INFO_PWMOD_PROMPT_NEW_PW.get());

        final byte[] pwBytes;
        try
        {
          pwBytes = PasswordReader.readPassword();
          if ((pwBytes == null) || (pwBytes.length == 0))
          {
            err();
            wrapErr(0, WRAP_COLUMN, ERR_PWMOD_PW_EMPTY.get());
            err();
            continue;
          }

          getOut().print(INFO_PWMOD_CONFIRM_NEW_PW.get());
          final byte[] confirmBytes = PasswordReader.readPassword();
          if ((confirmBytes == null) ||
               (! Arrays.equals(pwBytes, confirmBytes)))
          {
            Arrays.fill(pwBytes, (byte) 0x00);
            Arrays.fill(confirmBytes, (byte) 0x00);

            err();
            wrapErr(0, WRAP_COLUMN, ERR_PWMOD_NEW_PW_MISMATCH.get());
            err();
            continue;
          }

          Arrays.fill(confirmBytes, (byte) 0x00);
          return pwBytes;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_PWMOD_CANNOT_PROMPT_FOR_NEW_PW.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }
    }
    else if (generateClientSideNewPassword.isPresent())
    {
      return generatePassword();
    }
    else
    {
      return null;
    }
  }



  /**
   * Generates a new password for the user.
   *
   * @return  The new password that was generated.
   */
  @NotNull()
  private byte[] generatePassword()
  {
    final int length = generatedPasswordLength.getValue();
    final StringBuilder generatedPassword = new StringBuilder(length);

    final SecureRandom random = CryptoHelper.getSecureRandom();
    final StringBuilder allPasswordCharacters = new StringBuilder();
    for (final String charSet : generatedPasswordCharacterSet.getValues())
    {
      allPasswordCharacters.append(charSet);

      // Pick one character at random from the provided set to include in the
      // password.
      generatedPassword.append(
           charSet.charAt(random.nextInt(charSet.length())));
    }


    // Choose as many additional characters (across all of the sets) as needed
    // to reach the desired length.
    while (generatedPassword.length() < length)
    {
      generatedPassword.append(allPasswordCharacters.charAt(
           random.nextInt(allPasswordCharacters.length())));
    }


    // Scramble the generated password.
    final StringBuilder scrambledPassword =
         new StringBuilder(generatedPassword.length());
    while (true)
    {
      if (generatedPassword.length() == 1)
      {
        scrambledPassword.append(generatedPassword.charAt(0));
        break;
      }
      else
      {
        final int pos = random.nextInt(generatedPassword.length());
        scrambledPassword.append(generatedPassword.charAt(pos));
        generatedPassword.deleteCharAt(pos);
      }
    }

    final String scrambledPasswordString = scrambledPassword.toString();
    out();
    wrapOut(0, WRAP_COLUMN,
         INFO_PWMOD_CLIENT_SIDE_GEN_PW.get(getToolName(),
              scrambledPasswordString));
    return StaticUtils.getBytes(scrambledPasswordString);
  }



  /**
   * Retrieves the controls that should be included in the password update
   * request.
   *
   * @return  The controls that should be included in the password update
   *          request, or an empty array if no controls should be included.
   *
   * @throws  LDAPException  If a problem occurs while trying to create any of
   *                         the controls.
   */
  @NotNull()
  private Control[] getUpdateControls()
          throws LDAPException
  {
    final List<Control> controls = new ArrayList<>();

    if (updateControl.isPresent())
    {
      controls.addAll(updateControl.getValues());
    }

    if (usePasswordPolicyControlOnUpdate.isPresent())
    {
      controls.add(new PasswordPolicyRequestControl());
    }

    if (noOperation.isPresent())
    {
      controls.add(new NoOpRequestControl());
    }

    if (getPasswordValidationDetails.isPresent())
    {
      controls.add(new PasswordValidationDetailsRequestControl());
    }

    if (retireCurrentPassword.isPresent())
    {
      controls.add(new RetirePasswordRequestControl(false));
    }

    if (purgeCurrentPassword.isPresent())
    {
      controls.add(new PurgePasswordRequestControl(false));
    }

    if (passwordUpdateBehavior.isPresent())
    {
      controls.add(LDAPModify.createPasswordUpdateBehaviorRequestControl(
           passwordUpdateBehavior.getIdentifierString(),
           passwordUpdateBehavior.getValues()));
    }

    if (operationPurpose.isPresent())
    {
      controls.add(new OperationPurposeRequestControl(false, getToolName(),
           getToolVersion(),
           LDAPPasswordModify.class.getName() + ".getUpdateControls",
           operationPurpose.getValue()));
    }

    if (useAssuredReplication.isPresent())
    {
      AssuredReplicationLocalLevel localLevel = null;
      if (assuredReplicationLocalLevel.isPresent())
      {
        final String level = assuredReplicationLocalLevel.getValue();
        if (level.equalsIgnoreCase(ASSURED_REPLICATION_LOCAL_LEVEL_NONE))
        {
          localLevel = AssuredReplicationLocalLevel.NONE;
        }
        else if (level.equalsIgnoreCase(
             ASSURED_REPLICATION_LOCAL_LEVEL_RECEIVED_ANY_SERVER))
        {
          localLevel = AssuredReplicationLocalLevel.RECEIVED_ANY_SERVER;
        }
        else if (level.equalsIgnoreCase(
             ASSURED_REPLICATION_LOCAL_LEVEL_PROCESSED_ALL_SERVERS))
        {
          localLevel = AssuredReplicationLocalLevel.PROCESSED_ALL_SERVERS;
        }
      }

      AssuredReplicationRemoteLevel remoteLevel = null;
      if (assuredReplicationRemoteLevel.isPresent())
      {
        final String level = assuredReplicationRemoteLevel.getValue();
        if (level.equalsIgnoreCase(ASSURED_REPLICATION_REMOTE_LEVEL_NONE))
        {
          remoteLevel = AssuredReplicationRemoteLevel.NONE;
        }
        else if (level.equalsIgnoreCase(
             ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ANY_REMOTE_LOCATION))
        {
          remoteLevel =
               AssuredReplicationRemoteLevel.RECEIVED_ANY_REMOTE_LOCATION;
        }
        else if (level.equalsIgnoreCase(
             ASSURED_REPLICATION_REMOTE_LEVEL_RECEIVED_ALL_REMOTE_LOCATIONS))
        {
          remoteLevel =
               AssuredReplicationRemoteLevel.RECEIVED_ALL_REMOTE_LOCATIONS;
        }
        else if (level.equalsIgnoreCase(
             ASSURED_REPLICATION_REMOTE_LEVEL_PROCESSED_ALL_REMOTE_SERVERS))
        {
          remoteLevel =
               AssuredReplicationRemoteLevel.PROCESSED_ALL_REMOTE_SERVERS;
        }
      }

      Long timeoutMillis = null;
      if (assuredReplicationTimeout.isPresent())
      {
        timeoutMillis =
             assuredReplicationTimeout.getValue(TimeUnit.MILLISECONDS);
      }

      controls.add(new AssuredReplicationRequestControl(true, localLevel,
           localLevel, remoteLevel, remoteLevel, timeoutMillis, false));
    }


    return controls.toArray(StaticUtils.NO_CONTROLS);
  }



  /**
   * Writes the provided message and sets it as the completion message.
   *
   * @param  isError  Indicates whether the message should be written to
   *                  standard error rather than standard output.
   * @param  message  The message to be written.
   */
  private void logCompletionMessage(final boolean isError,
                                    @NotNull final String message)
  {
    completionMessage.compareAndSet(null, message);

    if (isError)
    {
      wrapErr(0, WRAP_COLUMN, message);
    }
    else
    {
      wrapOut(0, WRAP_COLUMN, message);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void handleUnsolicitedNotification(
                   @NotNull final LDAPConnection connection,
                   @NotNull final ExtendedResult notification)
  {
    final ArrayList<String> lines = new ArrayList<>(10);
    ResultUtils.formatUnsolicitedNotification(lines, notification, true, 0,
         WRAP_COLUMN);
    for (final String line : lines)
    {
      err(line);
    }
    err();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples = new LinkedHashMap<>();

    examples.put(
         new String[]
         {
           "--hostname", "ds.example.com",
           "--port", "636",
           "--useSSL",
           "--userIdentity", "u:jdoe",
           "--promptForCurrentPassword",
           "--promptForNewPassword"
         },
         INFO_PWMOD_EXAMPLE_1.get());

    examples.put(
         new String[]
         {
           "--hostname", "ds.example.com",
           "--port", "636",
           "--useSSL",
           "--bindDN", "uid=admin,dc=example,dc=com",
           "--bindPasswordFile", "admin-password.txt",
           "--userIdentity", "uid=jdoe,ou=People,dc=example,dc=com",
           "--generateClientSideNewPassword",
           "--passwordChangeMethod", "ldap-modify"
         },
         INFO_PWMOD_EXAMPLE_2.get());

    return examples;
  }
}
