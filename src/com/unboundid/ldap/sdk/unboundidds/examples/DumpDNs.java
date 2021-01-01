/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.examples;



import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.IntermediateResponseListener;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StreamDirectoryValuesExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            StreamDirectoryValuesIntermediateResponse;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;



/**
 * This class provides a utility that uses the stream directory values extended
 * operation in order to obtain a listing of all entry DNs below a specified
 * base DN in the Directory Server.
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
 * The APIs demonstrated by this example include:
 * <UL>
 *   <LI>The use of the stream directory values extended operation.</LI>
 *   <LI>Intermediate response processing.</LI>
 *   <LI>The LDAP command-line tool API.</LI>
 *   <LI>Argument parsing.</LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class DumpDNs
       extends LDAPCommandLineTool
       implements IntermediateResponseListener
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 774432759537092866L;



  // The argument used to obtain the base DN.
  @Nullable private DNArgument baseDN;

  // The argument used to obtain the output file.
  @Nullable private FileArgument outputFile;

  // The number of DNs dumped.
  @NotNull private final AtomicLong dnsWritten;

  // The print stream that will be used to output the DNs.
  @Nullable private PrintStream outputStream;



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(@NotNull final String[] args)
  {
    final ResultCode resultCode = main(args, System.out, System.err);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args       The command line arguments provided to this program.
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   *
   * @return  A result code indicating whether the processing was successful.
   */
  @NotNull()
  public static ResultCode main(@NotNull final String[] args,
                                @Nullable final OutputStream outStream,
                                @Nullable final OutputStream errStream)
  {
    final DumpDNs tool = new DumpDNs(outStream, errStream);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool.
   *
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   */
  public DumpDNs(@Nullable final OutputStream outStream,
                 @Nullable final OutputStream errStream)
  {
    super(outStream, errStream);

    baseDN       = null;
    outputFile   = null;
    outputStream = null;
    dnsWritten   = new AtomicLong(0L);
  }



  /**
   * Retrieves the name of this tool.  It should be the name of the command used
   * to invoke this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "dump-dns";
  }



  /**
   * Retrieves a human-readable description for this tool.
   *
   * @return  A human-readable description for this tool.
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return "Obtain a listing of all of the DNs for all entries below a " +
         "specified base DN in the Directory Server.";
  }



  /**
   * Retrieves the version string for this tool.
   *
   * @return  The version string for this tool.
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * Indicates whether this tool should provide support for an interactive mode,
   * in which the tool offers a mode in which the arguments can be provided in
   * a text-driven menu rather than requiring them to be given on the command
   * line.  If interactive mode is supported, it may be invoked using the
   * "--interactive" argument.  Alternately, if interactive mode is supported
   * and {@link #defaultsToInteractiveMode()} returns {@code true}, then
   * interactive mode may be invoked by simply launching the tool without any
   * arguments.
   *
   * @return  {@code true} if this tool supports interactive mode, or
   *          {@code false} if not.
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool defaults to launching in interactive mode if
   * the tool is invoked without any command-line arguments.  This will only be
   * used if {@link #supportsInteractiveMode()} returns {@code true}.
   *
   * @return  {@code true} if this tool defaults to using interactive mode if
   *          launched without any command-line arguments, or {@code false} if
   *          not.
   */
  @Override()
  public boolean defaultsToInteractiveMode()
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
  @Override()
  protected boolean defaultToPromptForBindPassword()
  {
    return true;
  }



  /**
   * Indicates whether this tool supports the use of a properties file for
   * specifying default values for arguments that aren't specified on the
   * command line.
   *
   * @return  {@code true} if this tool supports the use of a properties file
   *          for specifying default values for arguments that aren't specified
   *          on the command line, or {@code false} if not.
   */
  @Override()
  public boolean supportsPropertiesFile()
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
  @Override()
  protected boolean includeAlternateLongIdentifiers()
  {
    return true;
  }



  /**
   * Indicates whether this tool should provide a command-line argument that
   * allows for low-level SSL debugging.  If this returns {@code true}, then an
   * "--enableSSLDebugging}" argument will be added that sets the
   * "javax.net.debug" system property to "all" before attempting any
   * communication.
   *
   * @return  {@code true} if this tool should offer an "--enableSSLDebugging"
   *          argument, or {@code false} if not.
   */
  @Override()
  protected boolean supportsSSLDebugging()
  {
    return true;
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
  @Override()
  public void addNonLDAPArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    baseDN = new DNArgument('b', "baseDN", true, 1, "{dn}",
         "The base DN below which to dump the DNs of all entries in the " +
              "Directory Server.");
    baseDN.addLongIdentifier("base-dn", true);
    parser.addArgument(baseDN);

    outputFile = new FileArgument('f', "outputFile", false, 1, "{path}",
         "The path of the output file to which the entry DNs will be " +
              "written.  If this is not provided, then entry DNs will be " +
              "written to standard output.", false, true, true, false);
    outputFile.addLongIdentifier("output-file", true);
    parser.addArgument(outputFile);
  }



  /**
   * Retrieves the connection options that should be used for connections that
   * are created with this command line tool.  Subclasses may override this
   * method to use a custom set of connection options.
   *
   * @return  The connection options that should be used for connections that
   *          are created with this command line tool.
   */
  @Override()
  @NotNull()
  public LDAPConnectionOptions getConnectionOptions()
  {
    final LDAPConnectionOptions options = new LDAPConnectionOptions();

    options.setUseSynchronousMode(true);
    options.setResponseTimeoutMillis(0L);

    return options;
  }



  /**
   * Performs the core set of processing for this tool.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Create the writer that will be used to write the DNs.
    final File f = outputFile.getValue();
    if (f == null)
    {
      outputStream = getOut();
    }
    else
    {
      try
      {
        outputStream =
             new PrintStream(new BufferedOutputStream(new FileOutputStream(f)));
      }
      catch (final IOException ioe)
      {
        err("Unable to open output file '", f.getAbsolutePath(),
             " for writing:  ", StaticUtils.getExceptionMessage(ioe));
        return ResultCode.LOCAL_ERROR;
      }
    }


    // Obtain a connection to the Directory Server.
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (final LDAPException le)
    {
      err("Unable to obtain a connection to the Directory Server:  ",
          le.getExceptionMessage());
      return le.getResultCode();
    }


    // Create the extended request.  Register this class as an intermediate
    // response listener, and indicate that we don't want any response time
    // limit.
    final StreamDirectoryValuesExtendedRequest streamValuesRequest =
         new StreamDirectoryValuesExtendedRequest(baseDN.getStringValue(),
              SearchScope.SUB, false, null, 1000);
    streamValuesRequest.setIntermediateResponseListener(this);
    streamValuesRequest.setResponseTimeoutMillis(0L);


    // Send the extended request to the server and get the result.
    try
    {
      final ExtendedResult streamValuesResult =
           conn.processExtendedOperation(streamValuesRequest);
      err("Processing completed.  ", dnsWritten.get(), " DNs written.");
      return streamValuesResult.getResultCode();
    }
    catch (final LDAPException le)
    {
      err("Unable  to send the stream directory values extended request to " +
          "the Directory Server:  ", le.getExceptionMessage());
      return le.getResultCode();
    }
    finally
    {
      if (f != null)
      {
        outputStream.close();
      }

      conn.close();
    }
  }



  /**
   * Retrieves a set of information that may be used to generate example usage
   * information.  Each element in the returned map should consist of a map
   * between an example set of arguments and a string that describes the
   * behavior of the tool when invoked with that set of arguments.
   *
   * @return  A set of information that may be used to generate example usage
   *          information.  It may be {@code null} or empty if no example usage
   *          information is available.
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> exampleMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));

    final String[] args =
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--bindDN", "uid=admin,dc=example,dc=com",
      "--bindPassword", "password",
      "--baseDN", "dc=example,dc=com",
      "--outputFile", "example-dns.txt",
    };
    exampleMap.put(args,
         "Dump all entry DNs at or below 'dc=example,dc=com' to the file " +
              "'example-dns.txt'");

    return exampleMap;
  }



  /**
   * Indicates that the provided intermediate response has been returned by the
   * server and may be processed by this intermediate response listener.  In
   * this case, it will
   *
   * @param  intermediateResponse  The intermediate response that has been
   *                               returned by the server.
   */
  @Override()
  public void intermediateResponseReturned(
                   @NotNull final IntermediateResponse intermediateResponse)
  {
    // Try to parse the intermediate response as a stream directory values
    // intermediate response.
    final StreamDirectoryValuesIntermediateResponse streamValuesIR;
    try
    {
      streamValuesIR =
           new StreamDirectoryValuesIntermediateResponse(intermediateResponse);
    }
    catch (final LDAPException le)
    {
      err("Unable to parse an intermediate response message as a stream " +
          "directory values intermediate response:  ",
          le.getExceptionMessage());
      return;
    }

    final String diagnosticMessage = streamValuesIR.getDiagnosticMessage();
    if ((diagnosticMessage != null) && (! diagnosticMessage.isEmpty()))
    {
      err(diagnosticMessage);
    }


    final List<ASN1OctetString> values = streamValuesIR.getValues();
    if ((values != null) && (! values.isEmpty()))
    {
      for (final ASN1OctetString s : values)
      {
        outputStream.println(s.toString());
      }

      final long updatedCount = dnsWritten.addAndGet(values.size());
      if (outputFile.isPresent())
      {
        err(updatedCount, " DNs written.");
      }
    }
  }
}
