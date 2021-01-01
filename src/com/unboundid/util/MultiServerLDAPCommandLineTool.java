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
package com.unboundid.util;



import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.SocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import com.unboundid.ldap.sdk.BindRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.PostConnectProcessor;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.SingleServerSet;
import com.unboundid.ldap.sdk.StartTLSPostConnectProcessor;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
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
 * This class provides a basis for developing command-line tools that have the
 * ability to communicate with multiple directory servers, potentially with
 * very different settings for each.  For example, it may be used to help create
 * tools that move or compare data from one server to another.
 * <BR><BR>
 * Each server will be identified by a prefix and/or suffix that will be added
 * to the argument name (e.g., if the first server has a prefix of "source",
 * then the "hostname" argument will actually be "sourceHostname").  The
 * base names for the arguments this class supports include:
 * <UL>
 *   <LI>hostname -- Specifies the address of the directory server.  If this
 *       isn't specified, then a default of "localhost" will be used.</LI>
 *   <LI>port -- specifies the port number of the directory server.  If this
 *       isn't specified, then a default port of 389 will be used.</LI>
 *   <LI>bindDN -- Specifies the DN to use to bind to the directory server using
 *       simple authentication.  If this isn't specified, then simple
 *       authentication will not be performed.</LI>
 *   <LI>bindPassword -- Specifies the password to use when binding with simple
 *       authentication or a password-based SASL mechanism.</LI>
 *   <LI>bindPasswordFile -- Specifies the path to a file containing the
 *       password to use when binding with simple authentication or a
 *       password-based SASL mechanism.</LI>
 *   <LI>useSSL -- Indicates that communication with the server should be
 *       secured using SSL.</LI>
 *   <LI>useStartTLS -- Indicates that communication with the server should be
 *       secured using StartTLS.</LI>
 *   <LI>trustAll -- Indicates that the client should trust any certificate
 *       that the server presents to it.</LI>
 *   <LI>keyStorePath -- Specifies the path to the key store to use to obtain
 *       client certificates.</LI>
 *   <LI>keyStorePassword -- Specifies the password to use to access the
 *       contents of the key store.</LI>
 *   <LI>keyStorePasswordFile -- Specifies the path ot a file containing the
 *       password to use to access the contents of the key store.</LI>
 *   <LI>keyStoreFormat -- Specifies the format to use for the key store
 *       file.</LI>
 *   <LI>trustStorePath -- Specifies the path to the trust store to use to
 *       obtain client certificates.</LI>
 *   <LI>trustStorePassword -- Specifies the password to use to access the
 *       contents of the trust store.</LI>
 *   <LI>trustStorePasswordFile -- Specifies the path ot a file containing the
 *       password to use to access the contents of the trust store.</LI>
 *   <LI>trustStoreFormat -- Specifies the format to use for the trust store
 *       file.</LI>
 *   <LI>certNickname -- Specifies the nickname of the client certificate to
 *       use when performing SSL client authentication.</LI>
 *   <LI>saslOption -- Specifies a SASL option to use when performing SASL
 *       authentication.</LI>
 * </UL>
 * If SASL authentication is to be used, then a "mech" SASL option must be
 * provided to specify the name of the SASL mechanism to use.  Depending on the
 * SASL mechanism, additional SASL options may be required or optional.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_NOT_THREADSAFE)
public abstract class MultiServerLDAPCommandLineTool
       extends CommandLineTool
{
  // The set of prefixes and suffixes that will be used for server names.
  private final int numServers;
  @Nullable private final String[] serverNamePrefixes;
  @Nullable private final String[] serverNameSuffixes;

  // The set of arguments used to hold information about connection properties.
  @NotNull private final BooleanArgument[] trustAll;
  @NotNull private final BooleanArgument[] useSSL;
  @NotNull private final BooleanArgument[] useStartTLS;
  @NotNull private final DNArgument[]      bindDN;
  @NotNull private final FileArgument[]    bindPasswordFile;
  @NotNull private final FileArgument[]    keyStorePasswordFile;
  @NotNull private final FileArgument[]    trustStorePasswordFile;
  @NotNull private final IntegerArgument[] port;
  @NotNull private final StringArgument[]  bindPassword;
  @NotNull private final StringArgument[]  certificateNickname;
  @NotNull private final StringArgument[]  host;
  @NotNull private final StringArgument[]  keyStoreFormat;
  @NotNull private final StringArgument[]  keyStorePath;
  @NotNull private final StringArgument[]  keyStorePassword;
  @NotNull private final StringArgument[]  saslOption;
  @NotNull private final StringArgument[]  trustStoreFormat;
  @NotNull private final StringArgument[]  trustStorePath;
  @NotNull private final StringArgument[]  trustStorePassword;

  // Variables used when creating and authenticating connections.
  @NotNull private final BindRequest[]      bindRequest;
  @NotNull private final ServerSet[]        serverSet;
  @NotNull private final SSLSocketFactory[] startTLSSocketFactory;

  // An atomic reference to an aggregate trust manager that will check a
  // JVM-default set of trusted issuers, and then its own cache, before
  // prompting the user about whether to trust the presented certificate chain.
  // Re-using this trust manager will allow the tool to benefit from a common
  // cache if multiple connections are needed.
  @NotNull private final AtomicReference<AggregateTrustManager>
       promptTrustManager;



  /**
   * Creates a new instance of this multi-server LDAP command-line tool.  At
   * least one of the set of server name prefixes and suffixes must be
   * non-{@code null}.  If both are non-{@code null}, then they must have the
   * same number of elements.
   *
   * @param  outStream           The output stream to use for standard output.
   *                             It may be {@code System.out} for the JVM's
   *                             default standard output stream, {@code null} if
   *                             no output should be generated, or a custom
   *                             output stream if the output should be sent to
   *                             an alternate location.
   * @param  errStream           The output stream to use for standard error.
   *                             It may be {@code System.err} for the JVM's
   *                             default standard error stream, {@code null} if
   *                             no output should be generated, or a custom
   *                             output stream if the output should be sent to
   *                             an alternate location.
   * @param  serverNamePrefixes  The prefixes to include before the names of
   *                             each of the parameters to identify each server.
   *                             It may be {@code null} if only suffixes should
   *                             be used.
   * @param  serverNameSuffixes  The suffixes to include after the names of each
   *                             of the parameters to identify each server.  It
   *                             may be {@code null} if only prefixes should be
   *                             used.
   *
   * @throws  LDAPSDKUsageException  If both the sets of server name prefixes
   *                                 and suffixes are {@code null} or empty, or
   *                                 if both sets are non-{@code null} but have
   *                                 different numbers of elements.
   */
  public MultiServerLDAPCommandLineTool(@Nullable final OutputStream outStream,
              @Nullable final OutputStream errStream,
              @Nullable final String[] serverNamePrefixes,
              @Nullable final String[] serverNameSuffixes)
         throws LDAPSDKUsageException
  {
    super(outStream, errStream);

    promptTrustManager = new AtomicReference<>();

    this.serverNamePrefixes = serverNamePrefixes;
    this.serverNameSuffixes = serverNameSuffixes;

    if (serverNamePrefixes == null)
    {
      if (serverNameSuffixes == null)
      {
        throw new LDAPSDKUsageException(
             ERR_MULTI_LDAP_TOOL_PREFIXES_AND_SUFFIXES_NULL.get());
      }
      else
      {
        numServers = serverNameSuffixes.length;
      }
    }
    else
    {
      numServers = serverNamePrefixes.length;

      if ((serverNameSuffixes != null) &&
          (serverNamePrefixes.length != serverNameSuffixes.length))
      {
        throw new LDAPSDKUsageException(
             ERR_MULTI_LDAP_TOOL_PREFIXES_AND_SUFFIXES_MISMATCH.get());
      }
    }

    if (numServers == 0)
    {
      throw new LDAPSDKUsageException(
           ERR_MULTI_LDAP_TOOL_PREFIXES_AND_SUFFIXES_EMPTY.get());
    }

    trustAll               = new BooleanArgument[numServers];
    useSSL                 = new BooleanArgument[numServers];
    useStartTLS            = new BooleanArgument[numServers];
    bindDN                 = new DNArgument[numServers];
    bindPasswordFile       = new FileArgument[numServers];
    keyStorePasswordFile   = new FileArgument[numServers];
    trustStorePasswordFile = new FileArgument[numServers];
    port                   = new IntegerArgument[numServers];
    bindPassword           = new StringArgument[numServers];
    certificateNickname    = new StringArgument[numServers];
    host                   = new StringArgument[numServers];
    keyStoreFormat         = new StringArgument[numServers];
    keyStorePath           = new StringArgument[numServers];
    keyStorePassword       = new StringArgument[numServers];
    saslOption             = new StringArgument[numServers];
    trustStoreFormat       = new StringArgument[numServers];
    trustStorePath         = new StringArgument[numServers];
    trustStorePassword     = new StringArgument[numServers];

    bindRequest           = new BindRequest[numServers];
    serverSet             = new ServerSet[numServers];
    startTLSSocketFactory = new SSLSocketFactory[numServers];
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public final void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    for (int i=0; i < numServers; i++)
    {
      final StringBuilder groupNameBuffer = new StringBuilder();
      if (serverNamePrefixes != null)
      {
        final String prefix = serverNamePrefixes[i].replace('-', ' ').trim();
        groupNameBuffer.append(StaticUtils.capitalize(prefix, true));
      }

      if (serverNameSuffixes != null)
      {
        if (groupNameBuffer.length() > 0)
        {
          groupNameBuffer.append(' ');
        }

        final String suffix = serverNameSuffixes[i].replace('-', ' ').trim();
        groupNameBuffer.append(StaticUtils.capitalize(suffix, true));
      }

      groupNameBuffer.append(' ');
      groupNameBuffer.append(INFO_MULTI_LDAP_TOOL_GROUP_CONN_AND_AUTH.get());
      final String groupName = groupNameBuffer.toString();


      host[i] = new StringArgument(null, genArgName(i, "hostname"), true, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_HOST.get(),
           INFO_LDAP_TOOL_DESCRIPTION_HOST.get(), "localhost");
      host[i].setArgumentGroupName(groupName);
      parser.addArgument(host[i]);

      port[i] = new IntegerArgument(null, genArgName(i, "port"), true, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_PORT.get(),
           INFO_LDAP_TOOL_DESCRIPTION_PORT.get(), 1, 65_535, 389);
      port[i].setArgumentGroupName(groupName);
      parser.addArgument(port[i]);

      bindDN[i] = new DNArgument(null, genArgName(i, "bindDN"), false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_DN.get(),
           INFO_LDAP_TOOL_DESCRIPTION_BIND_DN.get());
      bindDN[i].setArgumentGroupName(groupName);
      parser.addArgument(bindDN[i]);

      bindPassword[i] = new StringArgument(null, genArgName(i, "bindPassword"),
           false, 1, INFO_LDAP_TOOL_PLACEHOLDER_PASSWORD.get(),
           INFO_LDAP_TOOL_DESCRIPTION_BIND_PW.get());
      bindPassword[i].setSensitive(true);
      bindPassword[i].setArgumentGroupName(groupName);
      parser.addArgument(bindPassword[i]);

      bindPasswordFile[i] = new FileArgument(null,
           genArgName(i, "bindPasswordFile"), false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
           INFO_LDAP_TOOL_DESCRIPTION_BIND_PW_FILE.get(), true, true, true,
           false);
      bindPasswordFile[i].setArgumentGroupName(groupName);
      parser.addArgument(bindPasswordFile[i]);

      useSSL[i] = new BooleanArgument(null, genArgName(i, "useSSL"), 1,
           INFO_LDAP_TOOL_DESCRIPTION_USE_SSL.get());
      useSSL[i].setArgumentGroupName(groupName);
      parser.addArgument(useSSL[i]);

      useStartTLS[i] = new BooleanArgument(null, genArgName(i, "useStartTLS"),
           1, INFO_LDAP_TOOL_DESCRIPTION_USE_START_TLS.get());
      useStartTLS[i].setArgumentGroupName(groupName);
      parser.addArgument(useStartTLS[i]);

      trustAll[i] = new BooleanArgument(null, genArgName(i, "trustAll"), 1,
           INFO_LDAP_TOOL_DESCRIPTION_TRUST_ALL.get());
      trustAll[i].setArgumentGroupName(groupName);
      parser.addArgument(trustAll[i]);

      keyStorePath[i] = new StringArgument(null, genArgName(i, "keyStorePath"),
           false, 1, INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
           INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_PATH.get());
      keyStorePath[i].setArgumentGroupName(groupName);
      parser.addArgument(keyStorePath[i]);

      keyStorePassword[i] = new StringArgument(null,
           genArgName(i, "keyStorePassword"), false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_PASSWORD.get(),
           INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_PASSWORD.get());
      keyStorePassword[i].setSensitive(true);
      keyStorePassword[i].setArgumentGroupName(groupName);
      parser.addArgument(keyStorePassword[i]);

      keyStorePasswordFile[i] = new FileArgument(null,
           genArgName(i, "keyStorePasswordFile"), false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
           INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_PASSWORD_FILE.get(), true,
           true, true, false);
      keyStorePasswordFile[i].setArgumentGroupName(groupName);
      parser.addArgument(keyStorePasswordFile[i]);

      keyStoreFormat[i] = new StringArgument(null,
           genArgName(i, "keyStoreFormat"), false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_FORMAT.get(),
           INFO_LDAP_TOOL_DESCRIPTION_KEY_STORE_FORMAT.get());
      keyStoreFormat[i].setArgumentGroupName(groupName);
      parser.addArgument(keyStoreFormat[i]);

      trustStorePath[i] = new StringArgument(null,
           genArgName(i, "trustStorePath"), false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
           INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_PATH.get());
      trustStorePath[i].setArgumentGroupName(groupName);
      parser.addArgument(trustStorePath[i]);

      trustStorePassword[i] = new StringArgument(null,
           genArgName(i, "trustStorePassword"), false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_PASSWORD.get(),
           INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_PASSWORD.get());
      trustStorePassword[i].setSensitive(true);
      trustStorePassword[i].setArgumentGroupName(groupName);
      parser.addArgument(trustStorePassword[i]);

      trustStorePasswordFile[i] = new FileArgument(null,
           genArgName(i, "trustStorePasswordFile"), false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_PATH.get(),
           INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_PASSWORD_FILE.get(), true,
           true, true, false);
      trustStorePasswordFile[i].setArgumentGroupName(groupName);
      parser.addArgument(trustStorePasswordFile[i]);

      trustStoreFormat[i] = new StringArgument(null,
           genArgName(i, "trustStoreFormat"), false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_FORMAT.get(),
           INFO_LDAP_TOOL_DESCRIPTION_TRUST_STORE_FORMAT.get());
      trustStoreFormat[i].setArgumentGroupName(groupName);
      parser.addArgument(trustStoreFormat[i]);

      certificateNickname[i] = new StringArgument(null,
           genArgName(i, "certNickname"), false, 1,
           INFO_LDAP_TOOL_PLACEHOLDER_CERT_NICKNAME.get(),
           INFO_LDAP_TOOL_DESCRIPTION_CERT_NICKNAME.get());
      certificateNickname[i].setArgumentGroupName(groupName);
      parser.addArgument(certificateNickname[i]);

      saslOption[i] = new StringArgument(null, genArgName(i, "saslOption"),
           false, 0, INFO_LDAP_TOOL_PLACEHOLDER_SASL_OPTION.get(),
           INFO_LDAP_TOOL_DESCRIPTION_SASL_OPTION.get());
      saslOption[i].setArgumentGroupName(groupName);
      parser.addArgument(saslOption[i]);

      parser.addDependentArgumentSet(bindDN[i], bindPassword[i],
           bindPasswordFile[i]);

      parser.addExclusiveArgumentSet(useSSL[i], useStartTLS[i]);
      parser.addExclusiveArgumentSet(bindPassword[i], bindPasswordFile[i]);
      parser.addExclusiveArgumentSet(keyStorePassword[i],
           keyStorePasswordFile[i]);
      parser.addExclusiveArgumentSet(trustStorePassword[i],
           trustStorePasswordFile[i]);
      parser.addExclusiveArgumentSet(trustAll[i], trustStorePath[i]);
    }

    addNonLDAPArguments(parser);
  }



  /**
   * Constructs the name to use for an argument from the given base and the
   * appropriate prefix and suffix.
   *
   * @param  index  The index into the set of prefixes and suffixes.
   * @param  base   The base name for the argument.
   *
   * @return  The constructed argument name.
   */
  @NotNull()
  private String genArgName(final int index, @NotNull final String base)
  {
    final StringBuilder buffer = new StringBuilder();

    if (serverNamePrefixes != null)
    {
      buffer.append(serverNamePrefixes[index]);

      if (base.equals("saslOption"))
      {
        buffer.append("SASLOption");
      }
      else
      {
        buffer.append(StaticUtils.capitalize(base));
      }
    }
    else
    {
      buffer.append(base);
    }

    if (serverNameSuffixes != null)
    {
      buffer.append(serverNameSuffixes[index]);
    }

    return buffer.toString();
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
    doExtendedNonLDAPArgumentValidation();
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
   * Retrieves a connection that may be used to communicate with the indicated
   * directory server.
   * <BR><BR>
   * Note that this method is threadsafe and may be invoked by multiple threads
   * accessing the same instance only while that instance is in the process of
   * invoking the {@link #doToolProcessing} method.
   *
   * @param  serverIndex  The zero-based index of the server to which the
   *                      connection should be established.
   *
   * @return  A connection that may be used to communicate with the indicated
   *          directory server.
   *
   * @throws  LDAPException  If a problem occurs while creating the connection.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  @NotNull()
  public final LDAPConnection getConnection(final int serverIndex)
         throws LDAPException
  {
    final LDAPConnection connection = getUnauthenticatedConnection(serverIndex);

    try
    {
      if (bindRequest[serverIndex] != null)
      {
        connection.bind(bindRequest[serverIndex]);
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
   * with the indicated directory server.
   * <BR><BR>
   * Note that this method is threadsafe and may be invoked by multiple threads
   * accessing the same instance only while that instance is in the process of
   * invoking the {@link #doToolProcessing} method.
   *
   * @param  serverIndex  The zero-based index of the server to which the
   *                      connection should be established.
   *
   * @return  An unauthenticated connection that may be used to communicate with
   *          the indicated directory server.
   *
   * @throws  LDAPException  If a problem occurs while creating the connection.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  @NotNull()
  public final LDAPConnection getUnauthenticatedConnection(
                                   final int serverIndex)
         throws LDAPException
  {
    if (serverSet[serverIndex] == null)
    {
      serverSet[serverIndex]   = createServerSet(serverIndex);
      bindRequest[serverIndex] = createBindRequest(serverIndex);
    }

    final LDAPConnection connection = serverSet[serverIndex].getConnection();

    if (useStartTLS[serverIndex].isPresent())
    {
      try
      {
        final ExtendedResult extendedResult =
             connection.processExtendedOperation(new StartTLSExtendedRequest(
                  startTLSSocketFactory[serverIndex]));
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
   * Retrieves a connection pool that may be used to communicate with the
   * indicated directory server.
   * <BR><BR>
   * Note that this method is threadsafe and may be invoked by multiple threads
   * accessing the same instance only while that instance is in the process of
   * invoking the {@link #doToolProcessing} method.
   *
   * @param  serverIndex         The zero-based index of the server to which the
   *                             connection should be established.
   * @param  initialConnections  The number of connections that should be
   *                             initially established in the pool.
   * @param  maxConnections      The maximum number of connections to maintain
   *                             in the pool.
   *
   * @return  A connection that may be used to communicate with the indicated
   *          directory server.
   *
   * @throws  LDAPException  If a problem occurs while creating the connection
   *                         pool.
   */
  @ThreadSafety(level=ThreadSafetyLevel.METHOD_THREADSAFE)
  @NotNull()
  public final LDAPConnectionPool getConnectionPool(
                                       final int serverIndex,
                                       final int initialConnections,
                                       final int maxConnections)
            throws LDAPException
  {
    if (serverSet[serverIndex] == null)
    {
      serverSet[serverIndex]   = createServerSet(serverIndex);
      bindRequest[serverIndex] = createBindRequest(serverIndex);
    }

    PostConnectProcessor postConnectProcessor = null;
    if (useStartTLS[serverIndex].isPresent())
    {
      postConnectProcessor = new StartTLSPostConnectProcessor(
           startTLSSocketFactory[serverIndex]);
    }

    return new LDAPConnectionPool(serverSet[serverIndex],
         bindRequest[serverIndex], initialConnections, maxConnections,
         postConnectProcessor);
  }



  /**
   * Creates the server set to use when creating connections or connection
   * pools.
   *
   * @param  serverIndex  The zero-based index of the server to which the
   *                      connection should be established.
   *
   * @return  The server set to use when creating connections or connection
   *          pools.
   *
   * @throws  LDAPException  If a problem occurs while creating the server set.
   */
  @NotNull()
  public final ServerSet createServerSet(final int serverIndex)
         throws LDAPException
  {
    final SSLUtil sslUtil = createSSLUtil(serverIndex);

    SocketFactory socketFactory = null;
    if (useSSL[serverIndex].isPresent())
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
                  StaticUtils.getExceptionMessage(e)), e);
      }
    }
    else if (useStartTLS[serverIndex].isPresent())
    {
      try
      {
        startTLSSocketFactory[serverIndex] = sslUtil.createSSLSocketFactory();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDAP_TOOL_CANNOT_CREATE_SSL_SOCKET_FACTORY.get(
                  StaticUtils.getExceptionMessage(e)), e);
      }
    }

    return new SingleServerSet(host[serverIndex].getValue(),
         port[serverIndex].getValue(), socketFactory, getConnectionOptions());
  }



  /**
   * Creates the SSLUtil instance to use for secure communication.
   *
   * @param  serverIndex  The zero-based index of the server to which the
   *                      connection should be established.
   *
   * @return  The SSLUtil instance to use for secure communication, or
   *          {@code null} if secure communication is not needed.
   *
   * @throws  LDAPException  If a problem occurs while creating the SSLUtil
   *                         instance.
   */
  @Nullable()
  public final SSLUtil createSSLUtil(final int serverIndex)
         throws LDAPException
  {
    if (useSSL[serverIndex].isPresent() || useStartTLS[serverIndex].isPresent())
    {
      KeyManager keyManager = null;
      if (keyStorePath[serverIndex].isPresent())
      {
        char[] pw = null;
        if (keyStorePassword[serverIndex].isPresent())
        {
          pw = keyStorePassword[serverIndex].getValue().toCharArray();
        }
        else if (keyStorePasswordFile[serverIndex].isPresent())
        {
          try
          {
            pw = getPasswordFileReader().readPassword(
                 keyStorePasswordFile[serverIndex].getValue());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_LDAP_TOOL_CANNOT_READ_KEY_STORE_PASSWORD.get(
                      StaticUtils.getExceptionMessage(e)), e);
          }
        }

        try
        {
          keyManager = new KeyStoreKeyManager(
               keyStorePath[serverIndex].getValue(), pw,
               keyStoreFormat[serverIndex].getValue(),
               certificateNickname[serverIndex].getValue(), true);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_LDAP_TOOL_CANNOT_CREATE_KEY_MANAGER.get(
                    StaticUtils.getExceptionMessage(e)), e);
        }
      }

      TrustManager tm;
      if (trustAll[serverIndex].isPresent())
      {
        tm = new TrustAllTrustManager(false);
      }
      else if (trustStorePath[serverIndex].isPresent())
      {
        char[] pw = null;
        if (trustStorePassword[serverIndex].isPresent())
        {
          pw = trustStorePassword[serverIndex].getValue().toCharArray();
        }
        else if (trustStorePasswordFile[serverIndex].isPresent())
        {
          try
          {
            pw = getPasswordFileReader().readPassword(
                 trustStorePasswordFile[serverIndex].getValue());
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_LDAP_TOOL_CANNOT_READ_TRUST_STORE_PASSWORD.get(
                      StaticUtils.getExceptionMessage(e)), e);
          }
        }

        tm = new TrustStoreTrustManager(
             trustStorePath[serverIndex].getValue(), pw,
             trustStoreFormat[serverIndex].getValue(), true);
      }
      else
      {
        tm = promptTrustManager.get();
        if (tm == null)
        {
          final AggregateTrustManager atm =
               InternalSDKHelper.getPreferredPromptTrustManagerChain(null);
          if (promptTrustManager.compareAndSet(null, atm))
          {
            tm = atm;
          }
          else
          {
            tm = promptTrustManager.get();
          }
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
   * Creates the bind request to use to authenticate to the indicated server.
   *
   * @param  serverIndex  The zero-based index of the server to which the
   *                      connection should be established.
   *
   * @return  The bind request to use to authenticate to the indicated server,
   *          or {@code null} if no bind should be performed.
   *
   * @throws  LDAPException  If a problem occurs while creating the bind
   *                         request.
   */
  @Nullable()
  public final BindRequest createBindRequest(final int serverIndex)
         throws LDAPException
  {
    final String pw;
    if (bindPassword[serverIndex].isPresent())
    {
      pw = bindPassword[serverIndex].getValue();
    }
    else if (bindPasswordFile[serverIndex].isPresent())
    {
      try
      {
        pw = new String(getPasswordFileReader().readPassword(
             bindPasswordFile[serverIndex].getValue()));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_LDAP_TOOL_CANNOT_READ_BIND_PASSWORD.get(
                  StaticUtils.getExceptionMessage(e)), e);
      }
    }
    else
    {
      pw = null;
    }

    if (saslOption[serverIndex].isPresent())
    {
      final String dnStr;
      if (bindDN[serverIndex].isPresent())
      {
        dnStr = bindDN[serverIndex].getValue().toString();
      }
      else
      {
        dnStr = null;
      }

      return SASLUtils.createBindRequest(dnStr, pw, null,
           saslOption[serverIndex].getValues());
    }
    else if (bindDN[serverIndex].isPresent())
    {
      return new SimpleBindRequest(bindDN[serverIndex].getValue(), pw);
    }
    else
    {
      return null;
    }
  }
}
