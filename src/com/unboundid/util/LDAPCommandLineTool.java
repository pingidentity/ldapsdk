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
package com.unboundid.util;



import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import com.unboundid.ldap.sdk.AggregatePostConnectProcessor;
import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.EXTERNALBindRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPConnectionPoolHealthCheck;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.PostConnectProcessor;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.RoundRobinServerSet;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.SingleServerSet;
import com.unboundid.ldap.sdk.StartTLSPostConnectProcessor;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.args.Argument;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.ssl.AggregateTrustManager;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustAllTrustManager;
import com.unboundid.util.ssl.TrustStoreTrustManager;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a basis for developing command-line tools that
 * communicate with an LDAP directory server.  It provides a common set of
 * options for connecting and authenticating to a directory server, and then
 * provides a mechanism for obtaining connections and connection pools to use
 * when communicating with that server.
 * <BR><BR>
 * The arguments that this class supports include:
 * <UL>
 *   <LI>"-h {address}" or "--hostname {address}" -- Specifies the address of
 *       the directory server.  If this isn't specified, then a default of
 *       "localhost" will be used.</LI>
 *   <LI>"-p {port}" or "--port {port}" -- Specifies the port number of the
 *       directory server.  If this isn't specified, then a default port of 389
 *       will be used.</LI>
 *   <LI>"-D {bindDN}" or "--bindDN {bindDN}" -- Specifies the DN to use to bind
 *       to the directory server using simple authentication.  If this isn't
 *       specified, then simple authentication will not be performed.</LI>
 *   <LI>"-w {password}" or "--bindPassword {password}" -- Specifies the
 *       password to use when binding with simple authentication or a
 *       password-based SASL mechanism.</LI>
 *   <LI>"-j {path}" or "--bindPasswordFile {path}" -- Specifies the path to the
 *       file containing the password to use when binding with simple
 *       authentication or a password-based SASL mechanism.</LI>
 *   <LI>"--promptForBindPassword" -- Indicates that the tool should
 *       interactively prompt the user for the bind password.</LI>
 *   <LI>"-Z" or "--useSSL" -- Indicates that the communication with the server
 *       should be secured using SSL.</LI>
 *   <LI>"-q" or "--useStartTLS" -- Indicates that the communication with the
 *       server should be secured using StartTLS.</LI>
 *   <LI>"-X" or "--trustAll" -- Indicates that the client should trust any
 *       certificate that the server presents to it.</LI>
 *   <LI>"-K {path}" or "--keyStorePath {path}" -- Specifies the path to the
 *       key store to use to obtain client certificates.</LI>
 *   <LI>"-W {password}" or "--keyStorePassword {password}" -- Specifies the
 *       password to use to access the contents of the key store.</LI>
 *   <LI>"-u {path}" or "--keyStorePasswordFile {path}" -- Specifies the path to
 *       the file containing the password to use to access the contents of the
 *       key store.</LI>
 *   <LI>"--promptForKeyStorePassword" -- Indicates that the tool should
 *       interactively prompt the user for the key store password.</LI>
 *   <LI>"--keyStoreFormat {format}" -- Specifies the format to use for the key
 *       store file.</LI>
 *   <LI>"-P {path}" or "--trustStorePath {path}" -- Specifies the path to the
 *       trust store to use when determining whether to trust server
 *       certificates.</LI>
 *   <LI>"-T {password}" or "--trustStorePassword {password}" -- Specifies the
 *       password to use to access the contents of the trust store.</LI>
 *   <LI>"-U {path}" or "--trustStorePasswordFile {path}" -- Specifies the path
 *       to the file containing the password to use to access the contents of
 *       the trust store.</LI>
 *   <LI>"--promptForTrustStorePassword" -- Indicates that the tool should
 *       interactively prompt the user for the trust store password.</LI>
 *   <LI>"--trustStoreFormat {format}" -- Specifies the format to use for the
 *       trust store file.</LI>
 *   <LI>"-N {nickname}" or "--certNickname {nickname}" -- Specifies the
 *       nickname of the client certificate to use when performing SSL client
 *       authentication.</LI>
 *   <LI>"-o {name=value}" or "--saslOption {name=value}" -- Specifies a SASL
 *       option to use when performing SASL authentication.</LI>
 * </UL>
 * If SASL authentication is to be used, then a "mech" SASL option must be
 * provided to specify the name of the SASL mechanism to use (e.g.,
 * "--saslOption mech=EXTERNAL" indicates that the EXTERNAL mechanism should be
 * used).  Depending on the SASL mechanism, additional SASL options may be
 * required or optional.  They include:
 * <UL>
 *   <LI>
 *     mech=ANONYMOUS
 *     <UL>
 *       <LI>Required SASL options:  </LI>
 *       <LI>Optional SASL options:  trace</LI>
 *     </UL>
 *   </LI>
 *   <LI>
 *     mech=CRAM-MD5
 *     <UL>
 *       <LI>Required SASL options:  authID</LI>
 *       <LI>Optional SASL options:  </LI>
 *     </UL>
 *   </LI>
 *   <LI>
 *     mech=DIGEST-MD5
 *     <UL>
 *       <LI>Required SASL options:  authID</LI>
 *       <LI>Optional SASL options:  authzID, realm</LI>
 *     </UL>
 *   </LI>
 *   <LI>
 *     mech=EXTERNAL
 *     <UL>
 *       <LI>Required SASL options:  </LI>
 *       <LI>Optional SASL options:  </LI>
 *     </UL>
 *   </LI>
 *   <LI>
 *     mech=GSSAPI
 *     <UL>
 *       <LI>Required SASL options:  authID</LI>
 *       <LI>Optional SASL options:  authzID, configFile, debug, protocol,
 *                realm, kdcAddress, useTicketCache, requireCache,
 *                renewTGT, ticketCachePath</LI>
 *     </UL>
 *   </LI>
 *   <LI>
 *     mech=PLAIN
 *     <UL>
 *       <LI>Required SASL options:  authID</LI>
 *       <LI>Optional SASL options:  authzID</LI>
 *     </UL>
 *   </LI>
 * </UL>
 * <BR><BR>
 * Note that in general, methods in this class are not threadsafe.  However, the
 * {@link #getConnection()} and {@link #getConnectionPool(int,int)} methods may
 * be invoked concurrently by multiple threads accessing the same instance only
 * while that instance is in the process of invoking the
 * {@link #doToolProcessing()} method.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class LDAPCommandLineTool
       extends CommandLineTool
{
  // Arguments used to communicate with an LDAP directory server.
  @Nullable private BooleanArgument helpSASL                    = null;
  @Nullable private BooleanArgument enableSSLDebugging          = null;
  @Nullable private BooleanArgument promptForBindPassword       = null;
  @Nullable private BooleanArgument promptForKeyStorePassword   = null;
  @Nullable private BooleanArgument promptForTrustStorePassword = null;
  @Nullable private BooleanArgument trustAll                    = null;
  @Nullable private BooleanArgument useSASLExternal             = null;
  @Nullable private BooleanArgument useSSL                      = null;
  @Nullable private BooleanArgument useStartTLS                 = null;
  @Nullable private DNArgument      bindDN                      = null;
  @Nullable private FileArgument    bindPasswordFile            = null;
  @Nullable private FileArgument    keyStorePasswordFile        = null;
  @Nullable private FileArgument    trustStorePasswordFile      = null;
  @Nullable private IntegerArgument port                        = null;
  @Nullable private StringArgument  bindPassword                = null;
  @Nullable private StringArgument  certificateNickname         = null;
  @Nullable private StringArgument  host                        = null;
  @Nullable private StringArgument  keyStoreFormat              = null;
  @Nullable private StringArgument  keyStorePath                = null;
  @Nullable private StringArgument  keyStorePassword            = null;
  @Nullable private StringArgument  saslOption                  = null;
  @Nullable private StringArgument  trustStoreFormat            = null;
  @Nullable private StringArgument  trustStorePath              = null;
  @Nullable private StringArgument  trustStorePassword          = null;

  // Variables used when creating and authenticating connections.
  @Nullable private BindRequest      bindRequest           = null;
  @Nullable private ServerSet        serverSet             = null;
  @Nullable private SSLSocketFactory startTLSSocketFactory = null;

  // An atomic reference to an aggregate trust manager that will check a
  // JVM-default set of trusted issuers, and then its own cache, before
  // prompting the user about whether to trust the presented certificate chain.
  // Re-using this trust manager will allow the tool to benefit from a common
  // cache if multiple connections are needed.
  @NotNull private final AtomicReference<AggregateTrustManager>
       promptTrustManager;



  /**
   * Creates a new instance of this LDAP-enabled command-line tool with the
   * provided information.
   *
   * @param  outStream  The output stream to use for standard output.  It may be
   *                    {@code System.out} for the JVM's default standard output
   *                    stream, {@code null} if no output should be generated,
   *                    or a custom output stream if the output should be sent
   *                    to an alternate location.
   * @param  errStream  The output stream to use for standard error.  It may be
   *                    {@code System.err} for the JVM's default standard error
   *                    stream, {@code null} if no output should be generated,
   *                    or a custom output stream if the output should be sent
   *                    to an alternate location.
   */
  public LDAPCommandLineTool(@Nullable final OutputStream outStream,
                             @Nullable final OutputStream errStream)
  {
    super(outStream, errStream);

    promptTrustManager = new AtomicReference<>();
  }



  /**
   * Retrieves a set containing the long identifiers used for LDAP-related
   * arguments injected by this class.
   *
   * @param  tool  The tool to use to help make the determination.
   *
   * @return  A set containing the long identifiers used for LDAP-related
   *          arguments injected by this class.
   */
  @NotNull()
  static Set<String> getLongLDAPArgumentIdentifiers(
                          @NotNull final LDAPCommandLineTool tool)
  {
    final LinkedHashSet<String> ids =
         new LinkedHashSet<>(StaticUtils.computeMapCapacity(21));

    ids.add("hostname");
    ids.add("port");

    if (tool.supportsAuthentication())
    {
      ids.add("bindDN");
      ids.add("bindPassword");
      ids.add("bindPasswordFile");
      ids.add("promptForBindPassword");
    }

    ids.add("useSSL");
    ids.add("useStartTLS");
    ids.add("trustAll");
    ids.add("keyStorePath");
    ids.add("keyStorePassword");
    ids.add("keyStorePasswordFile");
    ids.add("promptForKeyStorePassword");
    ids.add("keyStoreFormat");
    ids.add("trustStorePath");
    ids.add("trustStorePassword");
    ids.add("trustStorePasswordFile");
    ids.add("promptForTrustStorePassword");
    ids.add("trustStoreFormat");
    ids.add("certNickname");

    if (tool.supportsAuthentication())
    {
      ids.add("saslOption");
      ids.add("useSASLExternal");
      ids.add("helpSASL");
    }

    return Collections.unmodifiableSet(ids);
  }



  /**
   * Retrieves a set containing any short identifiers that should be suppressed
   * in the set of generic tool arguments so that they can be used by a
   * tool-specific argument instead.
   *
   * @return  A set containing any short identifiers that should be suppressed
   *          in the set of generic tool arguments so that they can be used by a
   *          tool-specific argument instead.  It may be empty but must not be
   *          {@code null}.
   */
  @NotNull()
  protected Set<Character> getSuppressedShortIdentifiers()
  {
    return Collections.emptySet();
  }



  /**
   * Retrieves the provided character if it is not included in the set of
   * suppressed short identifiers.
   *
   * @param  id  The character to return if it is not in the set of suppressed
   *             short identifiers.  It must not be {@code null}.
   *
   * @return  The provided character, or {@code null} if it is in the set of
   *          suppressed short identifiers.
   */
  @Nullable()
  private Character getShortIdentifierIfNotSuppressed(
                         @NotNull final Character id)
  {
    if (getSuppressedShortIdentifiers().contains(id))
    {
      return null;
    }
    else
    {
      return id;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    final String argumentGroup;
    final boolean supportsAuthentication = supportsAuthentication();
    if (supportsAuthentication)
    {
      argumentGroup = INFO_LDAP_TOOL_ARG_GROUP_CONNECT_AND_AUTH.get();
    }
    else
    {
      argumentGroup = INFO_LDAP_TOOL_ARG_GROUP_CONNECT.get();
    }


    host = new StringArgument(getShortIdentifierIfNotSuppressed('h'),
         "hostname", true, (supportsMultipleServers() ? 0 : 1),
         INFO_LDAP_TOOL_PLACEHOLDER_HOST.get(),
         INFO_LDAP_TOOL_DESCRIPTION_HOST.get(), "localhost");
    if (includeAlternateLongIdentifiers())
    {
      host.addLongIdentifier("host", true);
      host.addLongIdentifier("address", true);
    }
    host.setArgumentGroupName(argumentGroup);
    parser.addArgument(host);

    port = new IntegerArgument(getShortIdentifierIfNotSuppressed('p'), "port",
         true, (supportsMultipleServers() ? 0 : 1),
         INFO_LDAP_TOOL_PLACEHOLDER_PORT.get(),
         INFO_LDAP_TOOL_DESCRIPTION_PORT.get(), 1, 65_535, 389);
    port.setArgumentGroupName(argumentGroup);
    parser.addArgument(port);

    if (supportsAuthentication)
    {
      bindDN = new DNArgument(getShortIdentifierIfNotSuppressed('D'), "bindDN",
           false, 1, INFO_LDAP_TOOL_PLACEHOLDER_DN.get(),
           INFO_LDAP_TOOL_DESCRIPTION_BIND_DN.get());
      bindDN.setArgumentGroupName(argumentGroup);
      if (includeAlternateLongIdentifiers())
      {
        bindDN.addLongIdentifier("bind-dn", true);
      }
      parser.addArgument(bindDN);

      bindPassword = new StringArgument(getShortIdentifierIfNotSuppressed('w'),
           "bindPassword", false, 1, INFO_LDAP_TOOL_PLACEHOLDER_PASSWORD.get(),
           INFO_LDAP_TOOL_DESCRIPTION_BIND_PW.get());
      bindPassword.setSensitive(true);
      bindPassword.setArgumentGroupName(argumentGroup);
      if (includeAlternateLongIdentifiers())
      {
        bindPassword.addLongIdentifier("bind-password", true);
      }
      parser.addArgument(bindPassword);

      bindPasswordFile = new FileArgument(
           getShortIdentifierIfNotSuppressed('j'), "bindPasswordFile", false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
           INFO_LDAP_TOOL_DESCRIPTION_BIND_PW_FILE.get(), true, true, true,
           false);
      bindPasswordFile.setArgumentGroupName(argumentGroup);
      if (includeAlternateLongIdentifiers())
      {
        bindPasswordFile.addLongIdentifier("bind-password-file", true);
      }
      parser.addArgument(bindPasswordFile);

      promptForBindPassword = new BooleanArgument(null, "promptForBindPassword",
           1, INFO_LDAP_TOOL_DESCRIPTION_BIND_PW_PROMPT.get());
      promptForBindPassword.setArgumentGroupName(argumentGroup);
      if (includeAlternateLongIdentifiers())
      {
        promptForBindPassword.addLongIdentifier("prompt-for-bind-password",
             true);
      }
      parser.addArgument(promptForBindPassword);
    }

    useSSL = new BooleanArgument(getShortIdentifierIfNotSuppressed('Z'),
         "useSSL", 1, INFO_LDAP_TOOL_DESCRIPTION_USE_SSL.get());
    useSSL.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      useSSL.addLongIdentifier("use-ssl", true);
    }
    parser.addArgument(useSSL);

    useStartTLS = new BooleanArgument(getShortIdentifierIfNotSuppressed('q'),
         "useStartTLS", 1, INFO_LDAP_TOOL_DESCRIPTION_USE_START_TLS.get());
    useStartTLS.setArgumentGroupName(argumentGroup);
      if (includeAlternateLongIdentifiers())
      {
        useStartTLS.addLongIdentifier("use-starttls", true);
        useStartTLS.addLongIdentifier("use-start-tls", true);
      }
    parser.addArgument(useStartTLS);

    trustAll = new BooleanArgument(getShortIdentifierIfNotSuppressed('X'),
         "trustAll", 1, INFO_LDAP_TOOL_DESCRIPTION_TRUST_ALL.get());
    trustAll.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      trustAll.addLongIdentifier("trustAllCertificates", true);
      trustAll.addLongIdentifier("trust-all", true);
      trustAll.addLongIdentifier("trust-all-certificates", true);
    }
    parser.addArgument(trustAll);

    keyStorePath = new StringArgument(getShortIdentifierIfNotSuppressed('K'),
         "keyStorePath", false, 1, INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
         INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_PATH.get());
    keyStorePath.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      keyStorePath.addLongIdentifier("key-store-path", true);
    }
    parser.addArgument(keyStorePath);

    keyStorePassword = new StringArgument(
         getShortIdentifierIfNotSuppressed('W'), "keyStorePassword", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_PASSWORD.get(),
         INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_PASSWORD.get());
    keyStorePassword.setSensitive(true);
    keyStorePassword.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      keyStorePassword.addLongIdentifier("keyStorePIN", true);
      keyStorePassword.addLongIdentifier("key-store-password", true);
      keyStorePassword.addLongIdentifier("key-store-pin", true);
    }
    parser.addArgument(keyStorePassword);

    keyStorePasswordFile = new FileArgument(
         getShortIdentifierIfNotSuppressed('u'), "keyStorePasswordFile", false,
         1, INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
         INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_PASSWORD_FILE.get());
    keyStorePasswordFile.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      keyStorePasswordFile.addLongIdentifier("keyStorePINFile", true);
      keyStorePasswordFile.addLongIdentifier("key-store-password-file", true);
      keyStorePasswordFile.addLongIdentifier("key-store-pin-file", true);
    }
    parser.addArgument(keyStorePasswordFile);

    promptForKeyStorePassword = new BooleanArgument(null,
         "promptForKeyStorePassword", 1,
         INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_PASSWORD_PROMPT.get());
    promptForKeyStorePassword.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      promptForKeyStorePassword.addLongIdentifier("promptForKeyStorePIN", true);
      promptForKeyStorePassword.addLongIdentifier(
           "prompt-for-key-store-password", true);
      promptForKeyStorePassword.addLongIdentifier("prompt-for-key-store-pin",
           true);
    }
    parser.addArgument(promptForKeyStorePassword);

    keyStoreFormat = new StringArgument(null, "keyStoreFormat", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_FORMAT.get(),
         INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_FORMAT.get());
    keyStoreFormat.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      keyStoreFormat.addLongIdentifier("keyStoreType", true);
      keyStoreFormat.addLongIdentifier("key-store-format", true);
      keyStoreFormat.addLongIdentifier("key-store-type", true);
    }
    parser.addArgument(keyStoreFormat);

    trustStorePath = new StringArgument(getShortIdentifierIfNotSuppressed('P'),
         "trustStorePath", false, 1, INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
         INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_PATH.get());
    trustStorePath.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      trustStorePath.addLongIdentifier("trust-store-path", true);
    }
    parser.addArgument(trustStorePath);

    trustStorePassword = new StringArgument(
         getShortIdentifierIfNotSuppressed('T'), "trustStorePassword", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_PASSWORD.get(),
         INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_PASSWORD.get());
    trustStorePassword.setSensitive(true);
    trustStorePassword.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      trustStorePassword.addLongIdentifier("trustStorePIN", true);
      trustStorePassword.addLongIdentifier("trust-store-password", true);
      trustStorePassword.addLongIdentifier("trust-store-pin", true);
    }
    parser.addArgument(trustStorePassword);

    trustStorePasswordFile = new FileArgument(
         getShortIdentifierIfNotSuppressed('U'), "trustStorePasswordFile",
         false, 1, INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
         INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_PASSWORD_FILE.get());
    trustStorePasswordFile.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      trustStorePasswordFile.addLongIdentifier("trustStorePINFile", true);
      trustStorePasswordFile.addLongIdentifier("trust-store-password-file",
           true);
      trustStorePasswordFile.addLongIdentifier("trust-store-pin-file", true);
    }
    parser.addArgument(trustStorePasswordFile);

    promptForTrustStorePassword = new BooleanArgument(null,
         "promptForTrustStorePassword", 1,
         INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_PASSWORD_PROMPT.get());
    promptForTrustStorePassword.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      promptForTrustStorePassword.addLongIdentifier("promptForTrustStorePIN",
           true);
      promptForTrustStorePassword.addLongIdentifier(
           "prompt-for-trust-store-password", true);
      promptForTrustStorePassword.addLongIdentifier(
           "prompt-for-trust-store-pin", true);
    }
    parser.addArgument(promptForTrustStorePassword);

    trustStoreFormat = new StringArgument(null, "trustStoreFormat", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_FORMAT.get(),
         INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_FORMAT.get());
    trustStoreFormat.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      trustStoreFormat.addLongIdentifier("trustStoreType", true);
      trustStoreFormat.addLongIdentifier("trust-store-format", true);
      trustStoreFormat.addLongIdentifier("trust-store-type", true);
    }
    parser.addArgument(trustStoreFormat);

    certificateNickname = new StringArgument(
         getShortIdentifierIfNotSuppressed('N'), "certNickname", false, 1,
         INFO_LDAP_TOOL_PLACEHOLDER_CERT_NICKNAME.get(),
         INFO_LDAP_TOOL_DESCRIPTION_CERT_NICKNAME.get());
    certificateNickname.setArgumentGroupName(argumentGroup);
    if (includeAlternateLongIdentifiers())
    {
      certificateNickname.addLongIdentifier("certificateNickname", true);
      certificateNickname.addLongIdentifier("cert-nickname", true);
      certificateNickname.addLongIdentifier("certificate-nickname", true);
    }
    parser.addArgument(certificateNickname);

    if (supportsSSLDebugging())
    {
      enableSSLDebugging = new BooleanArgument(null, "enableSSLDebugging", 1,
           INFO_LDAP_TOOL_DESCRIPTION_ENABLE_SSL_DEBUGGING.get());
      enableSSLDebugging.setArgumentGroupName(argumentGroup);
      if (includeAlternateLongIdentifiers())
      {
        enableSSLDebugging.addLongIdentifier("enableTLSDebugging", true);
        enableSSLDebugging.addLongIdentifier("enableStartTLSDebugging", true);
        enableSSLDebugging.addLongIdentifier("enable-ssl-debugging", true);
        enableSSLDebugging.addLongIdentifier("enable-tls-debugging", true);
        enableSSLDebugging.addLongIdentifier("enable-starttls-debugging", true);
        enableSSLDebugging.addLongIdentifier("enable-start-tls-debugging",
             true);
      }
      parser.addArgument(enableSSLDebugging);
      addEnableSSLDebuggingArgument(enableSSLDebugging);
    }

    if (supportsAuthentication)
    {
      saslOption = new StringArgument(getShortIdentifierIfNotSuppressed('o'),
           "saslOption", false, 0, INFO_LDAP_TOOL_PLACEHOLDER_SASL_OPTION.get(),
           INFO_LDAP_TOOL_DESCRIPTION_SASL_OPTION.get());
      saslOption.setArgumentGroupName(argumentGroup);
      if (includeAlternateLongIdentifiers())
      {
        saslOption.addLongIdentifier("sasl-option", true);
      }
      parser.addArgument(saslOption);

      useSASLExternal = new BooleanArgument(null, "useSASLExternal", 1,
           INFO_LDAP_TOOL_DESCRIPTION_USE_SASL_EXTERNAL.get());
      useSASLExternal.setArgumentGroupName(argumentGroup);
      if (includeAlternateLongIdentifiers())
      {
        useSASLExternal.addLongIdentifier("use-sasl-external", true);
      }
      parser.addArgument(useSASLExternal);

      if (supportsSASLHelp())
      {
        helpSASL = new BooleanArgument(null, "helpSASL",
             INFO_LDAP_TOOL_DESCRIPTION_HELP_SASL.get());
        helpSASL.setArgumentGroupName(argumentGroup);
        if (includeAlternateLongIdentifiers())
        {
          helpSASL.addLongIdentifier("help-sasl", true);
        }
        helpSASL.setUsageArgument(true);
        parser.addArgument(helpSASL);
        setHelpSASLArgument(helpSASL);
      }
    }


    // Both useSSL and useStartTLS cannot be used together.
    parser.addExclusiveArgumentSet(useSSL, useStartTLS);

    // Only one option may be used for specifying the key store password.
    parser.addExclusiveArgumentSet(keyStorePassword, keyStorePasswordFile,
         promptForKeyStorePassword);

    // Only one option may be used for specifying the trust store password.
    parser.addExclusiveArgumentSet(trustStorePassword, trustStorePasswordFile,
         promptForTrustStorePassword);

    // It doesn't make sense to provide a trust store path if any server
    // certificate should be trusted.
    parser.addExclusiveArgumentSet(trustAll, trustStorePath);

    // If a key store password is provided, then a key store path must have also
    // been provided.
    parser.addDependentArgumentSet(keyStorePassword, keyStorePath);
    parser.addDependentArgumentSet(keyStorePasswordFile, keyStorePath);
    parser.addDependentArgumentSet(promptForKeyStorePassword, keyStorePath);

    // If a trust store password is provided, then a trust store path must have
    // also been provided.
    parser.addDependentArgumentSet(trustStorePassword, trustStorePath);
    parser.addDependentArgumentSet(trustStorePasswordFile, trustStorePath);
    parser.addDependentArgumentSet(promptForTrustStorePassword, trustStorePath);

    // If a key or trust store path is provided, then the tool must either use
    // SSL or StartTLS.
    parser.addDependentArgumentSet(keyStorePath, useSSL, useStartTLS);
    parser.addDependentArgumentSet(trustStorePath, useSSL, useStartTLS);

    // If the tool should trust all server certificates, then the tool must
    // either use SSL or StartTLS.
    parser.addDependentArgumentSet(trustAll, useSSL, useStartTLS);

    if (supportsAuthentication)
    {
      // If a bind DN was provided, then a bind password must have also been
      // provided unless defaultToPromptForBindPassword returns true.
      if (! defaultToPromptForBindPassword())
      {
        parser.addDependentArgumentSet(bindDN, bindPassword, bindPasswordFile,
             promptForBindPassword);
      }

      // The bindDN, saslOption, and useSASLExternal arguments are all mutually
      // exclusive.
      parser.addExclusiveArgumentSet(bindDN, saslOption, useSASLExternal);

      // Only one option may be used for specifying the bind password.
      parser.addExclusiveArgumentSet(bindPassword, bindPasswordFile,
           promptForBindPassword);

      // If a bind password was provided, then the a bind DN or SASL option
      // must have also been provided.
      parser.addDependentArgumentSet(bindPassword, bindDN, saslOption);
      parser.addDependentArgumentSet(bindPasswordFile, bindDN, saslOption);
      parser.addDependentArgumentSet(promptForBindPassword, bindDN, saslOption);
    }

    addNonLDAPArguments(parser);
  }



  /**
   * Adds the arguments needed by this command-line tool to the provided
   * argument parser which are not related to connecting or authenticating to
   * the directory server.
   *
   * @param  parser  The argument parser to which the arguments should be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding the arguments.
   */
  public abstract void addNonLDAPArguments(@NotNull ArgumentParser parser)
         throws ArgumentException;



  /**
   * {@inheritDoc}
   */
  @Override()
  public final void doExtendedArgumentValidation()
         throws ArgumentException
  {
    // If more than one hostname or port number was provided, then make sure
    // that the same number of values were provided for each.
    if ((host.getValues().size() > 1) || (port.getValues().size() > 1))
    {
      if (host.getValues().size() != port.getValues().size())
      {
        throw new ArgumentException(
             ERR_LDAP_TOOL_HOST_PORT_COUNT_MISMATCH.get(
                  host.getLongIdentifier(), port.getLongIdentifier()));
      }
    }


    doExtendedNonLDAPArgumentValidation();
  }



  /**
   * Indicates whether this tool should provide the arguments that allow it to
   * bind via simple or SASL authentication.
   *
   * @return  {@code true} if this tool should provide the arguments that allow
   *          it to bind via simple or SASL authentication, or {@code false} if
   *          not.
   */
  protected boolean supportsAuthentication()
  {
    return true;
  }



  /**
   * Indicates whether this tool should default to interactively prompting for
   * the bind password if a password is required but no argument was provided
   * to indicate how to get the password.
   *
   * @return  {@code true} if this tool should default to interactively
   *          prompting for the bind password, or {@code false} if not.
   */
  protected boolean defaultToPromptForBindPassword()
  {
    return false;
  }



  /**
   * Indicates whether this tool should provide a "--help-sasl" argument that
   * provides information about the supported SASL mechanisms and their
   * associated properties.
   *
   * @return  {@code true} if this tool should provide a "--help-sasl" argument,
   *          or {@code false} if not.
   */
  protected boolean supportsSASLHelp()
  {
    return true;
  }



  /**
   * Indicates whether the LDAP-specific arguments should include alternate
   * versions of all long identifiers that consist of multiple words so that
   * they are available in both camelCase and dash-separated versions.
   *
   * @return  {@code true} if this tool should provide multiple versions of
   *          long identifiers for LDAP-specific arguments, or {@code false} if
   *          not.
   */
  protected boolean includeAlternateLongIdentifiers()
  {
    return false;
  }



  /**
   * Retrieves a set of controls that should be included in any bind request
   * generated by this tool.
   *
   * @return  A set of controls that should be included in any bind request
   *          generated by this tool.  It may be {@code null} or empty if no
   *          controls should be included in the bind request.
   */
  @Nullable()
  protected List<Control> getBindControls()
  {
    return null;
  }



  /**
   * Indicates whether this tool supports creating connections to multiple
   * servers.  If it is to support multiple servers, then the "--hostname" and
   * "--port" arguments will be allowed to be provided multiple times, and
   * will be required to be provided the same number of times.  The same type of
   * communication security and bind credentials will be used for all servers.
   *
   * @return  {@code true} if this tool supports creating connections to
   *          multiple servers, or {@code false} if not.
   */
  protected boolean supportsMultipleServers()
  {
    return false;
  }



  /**
   * Indicates whether this tool should provide a command-line argument that
   * allows for low-level SSL debugging.  If this returns {@code true}, then an
   * "--enableSSLDebugging" argument will be added that sets the
   * "javax.net.debug" system property to "all" before attempting any
   * communication.
   *
   * @return  {@code true} if this tool should offer an "--enableSSLDebugging"
   *          argument, or {@code false} if not.
   */
  protected boolean supportsSSLDebugging()
  {
    return false;
  }



  /**
   * Performs any necessary processing that should be done to ensure that the
   * provided set of command-line arguments were valid.  This method will be
   * called after the basic argument parsing has been performed and after all
   * LDAP-specific argument validation has been processed, and immediately
   * before the {@link CommandLineTool#doToolProcessing} method is invoked.
   *
   * @throws  ArgumentException  If there was a problem with the command-line
   *                             arguments provided to this program.
   */
  public void doExtendedNonLDAPArgumentValidation()
         throws ArgumentException
  {
    // No processing will be performed by default.
  }



  /**
   * Retrieves the connection options that should be used for connections that
   * are created with this command line tool.  Subclasses may override this
   * method to use a custom set of connection options.
   *
   * @return  The connection options that should be used for connections that
   *          are created with this command line tool.
   */
  @NotNull()
  public LDAPConnectionOptions getConnectionOptions()
  {
    return new LDAPConnectionOptions();
  }



  /**
   * Retrieves a connection that may be used to communicate with the target
   * directory server.
   * <BR><BR>
   * Note that this method is threadsafe and may be invoked by multiple threads
   * accessing the same instance only while that instance is in the process of
   * invoking the {@link #doToolProcessing} method.
   *
   * @return  A connection that may be used to communicate with the target
   *          directory server.
   *
   * @throws  LDAPException  If a problem occurs while creating the connection.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  @NotNull()
  public final LDAPConnection getConnection()
         throws LDAPException
  {
    final LDAPConnection connection = getUnauthenticatedConnection();

    try
    {
      if (bindRequest != null)
      {
        connection.bind(bindRequest);
      }
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      connection.close();
      throw le;
    }

    return connection;
  }



  /**
   * Retrieves an unauthenticated connection that may be used to communicate
   * with the target directory server.
   * <BR><BR>
   * Note that this method is threadsafe and may be invoked by multiple threads
   * accessing the same instance only while that instance is in the process of
   * invoking the {@link #doToolProcessing} method.
   *
   * @return  An unauthenticated connection that may be used to communicate with
   *          the target directory server.
   *
   * @throws  LDAPException  If a problem occurs while creating the connection.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  @NotNull()
  public final LDAPConnection getUnauthenticatedConnection()
         throws LDAPException
  {
    if (serverSet == null)
    {
      serverSet   = createServerSet();
      bindRequest = createBindRequest();
    }

    final LDAPConnection connection = serverSet.getConnection();

    if (useStartTLS.isPresent())
    {
      try
      {
        final ExtendedResult extendedResult =
             connection.processExtendedOperation(
                  new StartTLSExtendedRequest(startTLSSocketFactory));
        if (! extendedResult.getResultCode().equals(ResultCode.SUCCESS))
        {
          throw new LDAPException(extendedResult.getResultCode(),
               ERR_LDAP_TOOL_START_TLS_FAILED.get(
                    extendedResult.getDiagnosticMessage()));
        }
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        connection.close();
        throw le;
      }
    }

    return connection;
  }



  /**
   * Retrieves a connection pool that may be used to communicate with the target
   * directory server.
   * <BR><BR>
   * Note that this method is threadsafe and may be invoked by multiple threads
   * accessing the same instance only while that instance is in the process of
   * invoking the {@link #doToolProcessing} method.
   *
   * @param  initialConnections  The number of connections that should be
   *                             initially established in the pool.
   * @param  maxConnections      The maximum number of connections to maintain
   *                             in the pool.
   *
   * @return  A connection that may be used to communicate with the target
   *          directory server.
   *
   * @throws  LDAPException  If a problem occurs while creating the connection
   *                         pool.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  @NotNull()
  public final LDAPConnectionPool getConnectionPool(
                                       final int initialConnections,
                                       final int maxConnections)
            throws LDAPException
  {
    return getConnectionPool(initialConnections, maxConnections, 1, null, null,
         true, null);
  }



  /**
   * Retrieves a connection pool that may be used to communicate with the target
   * directory server.
   * <BR><BR>
   * Note that this method is threadsafe and may be invoked by multiple threads
   * accessing the same instance only while that instance is in the process of
   * invoking the {@link #doToolProcessing} method.
   *
   * @param  initialConnections       The number of connections that should be
   *                                  initially established in the pool.
   * @param  maxConnections           The maximum number of connections to
   *                                  maintain in the pool.
   * @param  initialConnectThreads    The number of concurrent threads to use to
   *                                  establish the initial set of connections.
   *                                  A value greater than one indicates that
   *                                  the attempt to establish connections
   *                                  should be parallelized.
   * @param  beforeStartTLSProcessor  An optional post-connect processor that
   *                                  should be used for the connection pool and
   *                                  should be invoked before any StartTLS
   *                                  post-connect processor that may be needed
   *                                  based on the selected arguments.  It may
   *                                  be {@code null} if no such post-connect
   *                                  processor is needed.
   * @param  afterStartTLSProcessor   An optional post-connect processor that
   *                                  should be used for the connection pool and
   *                                  should be invoked after any StartTLS
   *                                  post-connect processor that may be needed
   *                                  based on the selected arguments.  It may
   *                                  be {@code null} if no such post-connect
   *                                  processor is needed.
   * @param  throwOnConnectFailure    If an exception should be thrown if a
   *                                  problem is encountered while attempting to
   *                                  create the specified initial number of
   *                                  connections.  If {@code true}, then the
   *                                  attempt to create the pool will fail if
   *                                  any connection cannot be established.  If
   *                                  {@code false}, then the pool will be
   *                                  created but may have fewer than the
   *                                  initial number of connections (or possibly
   *                                  no connections).
   * @param  healthCheck              An optional health check that should be
   *                                  configured for the connection pool.  It
   *                                  may be {@code null} if the default health
   *                                  checking should be performed.
   *
   * @return  A connection that may be used to communicate with the target
   *          directory server.
   *
   * @throws  LDAPException  If a problem occurs while creating the connection
   *                         pool.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  @NotNull()
  public final LDAPConnectionPool getConnectionPool(
              final int initialConnections, final int maxConnections,
              final int initialConnectThreads,
              @Nullable final PostConnectProcessor beforeStartTLSProcessor,
              @Nullable final PostConnectProcessor afterStartTLSProcessor,
              final boolean throwOnConnectFailure,
              @Nullable final LDAPConnectionPoolHealthCheck healthCheck)
            throws LDAPException
  {
    // Create the server set and bind request, if necessary.
    if (serverSet == null)
    {
      serverSet   = createServerSet();
      bindRequest = createBindRequest();
    }


    // Prepare the post-connect processor for the pool.
    final ArrayList<PostConnectProcessor> pcpList = new ArrayList<>(3);
    if (beforeStartTLSProcessor != null)
    {
      pcpList.add(beforeStartTLSProcessor);
    }

    if (useStartTLS.isPresent())
    {
      pcpList.add(new StartTLSPostConnectProcessor(startTLSSocketFactory));
    }

    if (afterStartTLSProcessor != null)
    {
      pcpList.add(afterStartTLSProcessor);
    }

    final PostConnectProcessor postConnectProcessor;
    switch (pcpList.size())
    {
      case 0:
        postConnectProcessor = null;
        break;
      case 1:
        postConnectProcessor = pcpList.get(0);
        break;
      default:
        postConnectProcessor = new AggregatePostConnectProcessor(pcpList);
        break;
    }

    return new LDAPConnectionPool(serverSet, bindRequest, initialConnections,
         maxConnections, initialConnectThreads, postConnectProcessor,
         throwOnConnectFailure, healthCheck);
  }



  /**
   * Creates the server set to use when creating connections or connection
   * pools.
   *
   * @return  The server set to use when creating connections or connection
   *          pools.
   *
   * @throws  LDAPException  If a problem occurs while creating the server set.
   */
  @NotNull()
  public ServerSet createServerSet()
         throws LDAPException
  {
    final SSLUtil sslUtil = createSSLUtil();

    SocketFactory socketFactory = null;
    if (useSSL.isPresent())
    {
      try
      {
        socketFactory = sslUtil.createSSLSocketFactory();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDAP_TOOL_CANNOT_CREATE_SSL_SOCKET_FACTORY.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
    else if (useStartTLS.isPresent())
    {
      try
      {
        startTLSSocketFactory = sslUtil.createSSLSocketFactory();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDAP_TOOL_CANNOT_CREATE_SSL_SOCKET_FACTORY.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    if (host.getValues().size() == 1)
    {
      return new SingleServerSet(host.getValue(), port.getValue(),
                                 socketFactory, getConnectionOptions());
    }
    else
    {
      final List<String>  hostList = host.getValues();
      final List<Integer> portList = port.getValues();

      final String[] hosts = new String[hostList.size()];
      final int[]    ports = new int[hosts.length];

      for (int i=0; i < hosts.length; i++)
      {
        hosts[i] = hostList.get(i);
        ports[i] = portList.get(i);
      }

      return new RoundRobinServerSet(hosts, ports, socketFactory,
                                     getConnectionOptions());
    }
  }



  /**
   * Creates the SSLUtil instance to use for secure communication.
   *
   * @return  The SSLUtil instance to use for secure communication, or
   *          {@code null} if secure communication is not needed.
   *
   * @throws  LDAPException  If a problem occurs while creating the SSLUtil
   *                         instance.
   */
  @Nullable()
  public SSLUtil createSSLUtil()
         throws LDAPException
  {
    return createSSLUtil(false);
  }



  /**
   * Creates the SSLUtil instance to use for secure communication.
   *
   * @param  force  Indicates whether to create the SSLUtil object even if
   *                neither the "--useSSL" nor the "--useStartTLS" argument was
   *                provided.  The key store and/or trust store paths must still
   *                have been provided.  This may be useful for tools that
   *                accept SSL-based communication but do not themselves intend
   *                to perform SSL-based communication as an LDAP client.
   *
   * @return  The SSLUtil instance to use for secure communication, or
   *          {@code null} if secure communication is not needed.
   *
   * @throws  LDAPException  If a problem occurs while creating the SSLUtil
   *                         instance.
   */
  @Nullable()
  public SSLUtil createSSLUtil(final boolean force)
         throws LDAPException
  {
    if (force || useSSL.isPresent() || useStartTLS.isPresent())
    {
      KeyManager keyManager = null;
      if (keyStorePath.isPresent())
      {
        char[] pw = null;
        if (keyStorePassword.isPresent())
        {
          pw = keyStorePassword.getValue().toCharArray();
        }
        else if (keyStorePasswordFile.isPresent())
        {
          try
          {
            pw = getPasswordFileReader().readPassword(
                 keyStorePasswordFile.getValue());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_LDAP_TOOL_CANNOT_READ_KEY_STORE_PASSWORD.get(
                      StaticUtils.getExceptionMessage(e)),
                 e);
          }
        }
        else if (promptForKeyStorePassword.isPresent())
        {
          getOut().print(INFO_LDAP_TOOL_ENTER_KEY_STORE_PASSWORD.get());
          pw = StaticUtils.toUTF8String(
               PasswordReader.readPassword()).toCharArray();
          getOut().println();
        }

        try
        {
          keyManager = new KeyStoreKeyManager(keyStorePath.getValue(), pw,
               keyStoreFormat.getValue(), certificateNickname.getValue(), true);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_LDAP_TOOL_CANNOT_CREATE_KEY_MANAGER.get(
                    StaticUtils.getExceptionMessage(e)),
               e);
        }
      }

      final TrustManager tm;
      if (trustAll.isPresent())
      {
        tm = new TrustAllTrustManager(false);
      }
      else if (trustStorePath.isPresent())
      {
        char[] pw = null;
        if (trustStorePassword.isPresent())
        {
          pw = trustStorePassword.getValue().toCharArray();
        }
        else if (trustStorePasswordFile.isPresent())
        {
          try
          {
            pw = getPasswordFileReader().readPassword(
                 trustStorePasswordFile.getValue());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_LDAP_TOOL_CANNOT_READ_TRUST_STORE_PASSWORD.get(
                      StaticUtils.getExceptionMessage(e)), e);
          }
        }
        else if (promptForTrustStorePassword.isPresent())
        {
          getOut().print(INFO_LDAP_TOOL_ENTER_TRUST_STORE_PASSWORD.get());
          pw = StaticUtils.toUTF8String(
               PasswordReader.readPassword()).toCharArray();
          getOut().println();
        }

        tm = new TrustStoreTrustManager(trustStorePath.getValue(), pw,
             trustStoreFormat.getValue(), true);
      }
      else if (promptTrustManager.get() != null)
      {
        tm = promptTrustManager.get();
      }
      else
      {
        final ArrayList<String> expectedAddresses = new ArrayList<>(5);
        if (useSSL.isPresent() || useStartTLS.isPresent())
        {
          expectedAddresses.addAll(host.getValues());
        }

        final AggregateTrustManager atm =
             InternalSDKHelper.getPreferredPromptTrustManagerChain(
                  expectedAddresses);
        if (promptTrustManager.compareAndSet(null, atm))
        {
          tm = atm;
        }
        else
        {
          tm = promptTrustManager.get();
        }
      }

      return new SSLUtil(keyManager, tm);
    }
    else
    {
      return null;
    }
  }



  /**
   * Creates the bind request to use to authenticate to the server.
   *
   * @return  The bind request to use to authenticate to the server, or
   *          {@code null} if no bind should be performed.
   *
   * @throws  LDAPException  If a problem occurs while creating the bind
   *                         request.
   */
  @Nullable()
  public BindRequest createBindRequest()
         throws LDAPException
  {
    if (! supportsAuthentication())
    {
      return null;
    }

    final Control[] bindControls;
    final List<Control> bindControlList = getBindControls();
    if ((bindControlList == null) || bindControlList.isEmpty())
    {
      bindControls = StaticUtils.NO_CONTROLS;
    }
    else
    {
      bindControls = new Control[bindControlList.size()];
      bindControlList.toArray(bindControls);
    }

    byte[] pw;
    if (bindPassword.isPresent())
    {
      pw = StaticUtils.getBytes(bindPassword.getValue());
    }
    else if (bindPasswordFile.isPresent())
    {
      try
      {
        final char[] pwChars = getPasswordFileReader().readPassword(
             bindPasswordFile.getValue());
        pw = StaticUtils.getBytes(new String(pwChars));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDAP_TOOL_CANNOT_READ_BIND_PASSWORD.get(
                  StaticUtils.getExceptionMessage(e)), e);
      }
    }
    else if (promptForBindPassword.isPresent())
    {
      getOriginalOut().print(INFO_LDAP_TOOL_ENTER_BIND_PASSWORD.get());
      pw = PasswordReader.readPassword();
      getOriginalOut().println();
    }
    else
    {
      pw = null;
    }

    if (saslOption.isPresent())
    {
      final String dnStr;
      if (bindDN.isPresent())
      {
        dnStr = bindDN.getValue().toString();
      }
      else
      {
        dnStr = null;
      }

      return SASLUtils.createBindRequest(dnStr, pw,
           defaultToPromptForBindPassword(), this, null,
           saslOption.getValues(), bindControls);
    }
    else if (useSASLExternal.isPresent())
    {
      return new EXTERNALBindRequest(bindControls);
    }
    else if (bindDN.isPresent())
    {
      if ((pw == null) && (! bindDN.getValue().isNullDN()) &&
          defaultToPromptForBindPassword())
      {
        getOriginalOut().print(INFO_LDAP_TOOL_ENTER_BIND_PASSWORD.get());
        pw = PasswordReader.readPassword();
        getOriginalOut().println();
      }

      return new SimpleBindRequest(bindDN.getValue(), pw, bindControls);
    }
    else
    {
      return null;
    }
  }



  /**
   * Indicates whether any of the LDAP-related arguments maintained by the
   * {@code LDAPCommandLineTool} class were provided on the command line.
   *
   * @return  {@code true} if any of the LDAP-related arguments maintained by
   *          the {@code LDAPCommandLineTool} were provided on the command line,
   *          or {@code false} if not.
   */
  public final boolean anyLDAPArgumentsProvided()
  {
    return isAnyPresent(host, port, bindDN, bindPassword, bindPasswordFile,
         promptForBindPassword, useSSL, useStartTLS, trustAll, keyStorePath,
         keyStorePassword, keyStorePasswordFile, promptForKeyStorePassword,
         keyStoreFormat, trustStorePath, trustStorePassword,
         trustStorePasswordFile, trustStoreFormat, certificateNickname,
         saslOption, useSASLExternal);
  }



  /**
   * Indicates whether at least one of the provided arguments was provided on
   * the command line.
   *
   * @param  args  The set of command-line arguments for which to make the
   *               determination.
   *
   * @return  {@code true} if at least one of the provided arguments was
   *          provided on the command line, or {@code false} if not.
   */
  private static boolean isAnyPresent(@NotNull final Argument... args)
  {
    for (final Argument a : args)
    {
      if ((a != null) && (a.getNumOccurrences() > 0))
      {
        return true;
      }
    }

    return false;
  }
}
