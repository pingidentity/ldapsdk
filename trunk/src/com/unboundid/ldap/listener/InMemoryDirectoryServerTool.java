/*
 * Copyright 2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011 UnboundID Corp.
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
package com.unboundid.ldap.listener;



import java.io.File;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.logging.FileHandler;
import java.util.logging.Level;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.MinimalLogFormatter;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.FileArgument;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides a command-line tool that can be used to run an instance
 * of the in-memory directory server.  Instances of the server may also be
 * created and controlled programmatically using the
 * {@link InMemoryDirectoryServer} class.
 * <BR><BR>
 * The following command-line arguments may be used with this class:
 * <UL>
 *   <LI>"-b {baseDN}" or "--baseDN {baseDN}" -- specifies a base DN to use for
 *       the server.  At least one base DN must be specified, and multiple
 *       base DNs may be provided as separate arguments.</LI>
 *   <LI>"-p {port}" or "--port {port}" -- specifies the port on which the
 *       server should listen for client connections.  If this is not provided,
 *       then a free port will be automatically chosen for use by the
 *       server.</LI>
 *   <LI>"-l {path}" or "--ldifFile {path}" -- specifies the path to an LDIF
 *       file to use to initially populate the server.  If this is not provided,
 *       then the server will initially be empty.  The LDIF file will not be
 *       updated as operations are processed in the server.</LI>
 *   <LI>"-L {path}" or "--logFile {path}" -- specifies the path to a file that
 *       should be used as a server access log.  If this is not provided, then
 *       no access logging will be performed.</LI>
 *   <LI>"-s {path}" or "--useSchema {path}" -- specifies the path to a file or
 *       directory containing schema definitions to use for the server.  If this
 *       is not provided, then the server will not perform any schema
 *       validation.  If the specified path represents a file, then it must be
 *       an LDIF file containing a valid LDAP subschema subentry.  If the path
 *       is a directory, then its files will be processed in lexicographic order
 *       by name.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class InMemoryDirectoryServerTool
       extends CommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6484637038039050412L;



  /**
   * The argument used to indicate that the default standard schema should be
   * used.
   */
  private BooleanArgument useDefaultSchemaArgument;



  /**
   * The argument used to specify the base DNs to use for the server.
   */
  private DNArgument baseDNArgument;



  /**
   * The argument used to specify the path to an LDIF file with data to use to
   * initially populate the server.
   */
  private FileArgument ldifFileArgument;



  /**
   * The argument used to specify the path to an access log file to which
   * information should be written about operations processed by the server.
   */
  private FileArgument logFileArgument;



  /**
   * The argument used to specify the path to a directory containing schema
   * definitions.
   */
  private FileArgument useSchemaFileArgument;



  /**
   * The argument used to specify the port on which the server should listen.
   */
  private IntegerArgument portArgument;



  /**
   * Parse the provided command line arguments and uses them to start the
   * directory server.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(final String... args)
  {
    final ResultCode resultCode = main(args, System.out, System.err);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Parse the provided command line arguments and uses them to start the
   * directory server.
   *
   * @param  outStream  The output stream to which standard out should be
   *                    written.  It may be {@code null} if output should be
   *                    suppressed.
   * @param  errStream  The output stream to which standard error should be
   *                    written.  It may be {@code null} if error messages
   *                    should be suppressed.
   * @param  args       The command line arguments provided to this program.
   *
   * @return  A result code indicating whether the processing was successful.
   */
  public static ResultCode main(final String[] args,
                                final OutputStream outStream,
                                final OutputStream errStream)
  {
    final InMemoryDirectoryServerTool tool =
         new InMemoryDirectoryServerTool(outStream, errStream);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool that use the provided output streams
   * for standard output and standard error.
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
  public InMemoryDirectoryServerTool(final OutputStream outStream,
                                     final OutputStream errStream)
  {
    super(outStream, errStream);

    baseDNArgument           = null;
    portArgument             = null;
    ldifFileArgument         = null;
    logFileArgument          = null;
    useDefaultSchemaArgument = null;
    useSchemaFileArgument    = null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolName()
  {
    return "in-memory-directory-server";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolDescription()
  {
    return INFO_MEM_DS_TOOL_DESC.get(InMemoryDirectoryServer.class.getName());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addToolArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    baseDNArgument = new DNArgument('b', "baseDN", true, 0,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_BASE_DN.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_BASE_DN.get());
    parser.addArgument(baseDNArgument);

    portArgument = new IntegerArgument('p', "port", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PORT.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_PORT.get(), 0, 65535);
    parser.addArgument(portArgument);

    ldifFileArgument = new FileArgument('l', "ldifFile", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PATH.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_LDIF_FILE.get(), true, true, true, false);
    parser.addArgument(ldifFileArgument);

    logFileArgument = new FileArgument('L', "logFile", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PATH.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_LOG_FILE.get(), false, true, true, false);
    parser.addArgument(logFileArgument);

    useDefaultSchemaArgument = new BooleanArgument('s', "useDefaultSchema",
         INFO_MEM_DS_TOOL_ARG_DESC_USE_DEFAULT_SCHEMA.get());
    parser.addArgument(useDefaultSchemaArgument);

    useSchemaFileArgument = new FileArgument('S', "useSchemaFile", false, 1,
         INFO_MEM_DS_TOOL_ARG_PLACEHOLDER_PATH.get(),
         INFO_MEM_DS_TOOL_ARG_DESC_USE_SCHEMA_FILE.get(), true, true, false,
         false);
    parser.addArgument(useSchemaFileArgument);

    parser.addExclusiveArgumentSet(useDefaultSchemaArgument,
         useSchemaFileArgument);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    // Create a base configuration.
    final InMemoryDirectoryServerConfig serverConfig;
    try
    {
      serverConfig = getConfig();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      err(ERR_MEM_DS_TOOL_ERROR_INITIALIZING_CONFIG.get(le.getMessage()));
      return le.getResultCode();
    }


    // Create the server instance using the provided configuration, but don't
    // start it yet.
    final InMemoryDirectoryServer server;
    try
    {
      server = new InMemoryDirectoryServer(serverConfig);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      err(ERR_MEM_DS_TOOL_ERROR_CREATING_SERVER_INSTANCE.get(le.getMessage()));
      return le.getResultCode();
    }


    // If an LDIF file was provided, then use it to populate the server.
    if (ldifFileArgument.isPresent())
    {
      final File ldifFile = ldifFileArgument.getValue();
      try
      {
        final int numEntries =
             server.initializeFromLDIF(true, ldifFile.getAbsolutePath());
        out(INFO_MEM_DS_TOOL_ADDED_ENTRIES_FROM_LDIF.get(numEntries,
             ldifFile.getAbsolutePath()));
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);
        err(ERR_MEM_DS_TOOL_ERROR_POPULATING_SERVER_INSTANCE.get(
             ldifFile.getAbsolutePath(), le.getMessage()));
        return le.getResultCode();
      }
    }


    // Start the server.
    try
    {
      server.startListening();
      out(INFO_MEM_DS_TOOL_LISTENING.get(server.getListenPort()));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      err(ERR_MEM_DS_TOOL_ERROR_STARTING_SERVER.get(
           StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }

    return ResultCode.SUCCESS;
  }



  /**
   * Creates a server configuration based on information provided with
   * command line arguments.
   *
   * @return  The configuration that was created.
   *
   * @throws  LDAPException  If a problem is encountered while creating the
   *                         configuration.
   */
  private InMemoryDirectoryServerConfig getConfig()
          throws LDAPException
  {
    final List<DN> dnList = baseDNArgument.getValues();
    final DN[] baseDNs = new DN[dnList.size()];
    dnList.toArray(baseDNs);

    final InMemoryDirectoryServerConfig serverConfig =
         new InMemoryDirectoryServerConfig(baseDNs);


    // If a listen port was specified, then update the configuration to use it.
    if (portArgument.isPresent())
    {
      serverConfig.setListenPort(portArgument.getValue());
    }


    // If schema should be used, then get it.
    if (useDefaultSchemaArgument.isPresent())
    {
      serverConfig.setSchema(Schema.getDefaultStandardSchema());
    }
    else if (useSchemaFileArgument.isPresent())
    {
      final File f = useSchemaFileArgument.getValue();
      if (f.exists())
      {
        final ArrayList<File> schemaFiles = new ArrayList<File>(1);
        if (f.isFile())
        {
          schemaFiles.add(f);
        }
        else
        {
          for (final File subFile : f.listFiles())
          {
            if (subFile.isFile())
            {
              schemaFiles.add(subFile);
            }
          }
        }

        if (! schemaFiles.isEmpty())
        {
          try
          {
            serverConfig.setSchema(Schema.getSchema(schemaFiles));
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
            throw new LDAPException(ResultCode.LOCAL_ERROR,
                 ERR_MEM_DS_TOOL_ERROR_READING_SCHEMA.get(
                      f.getAbsolutePath(), StaticUtils.getExceptionMessage(e)),
                 e);
          }
        }
      }
    }


    // If a log file was specified, then create the log handler.
    if (logFileArgument.isPresent())
    {
      final File logFile = logFileArgument.getValue();
      try
      {
        final FileHandler logFileHandler =
             new FileHandler(logFile.getAbsolutePath(), true);
        logFileHandler.setLevel(Level.INFO);
        logFileHandler.setFormatter(new MinimalLogFormatter(null, false, false,
             true));
        serverConfig.setAccessLogHandler(logFileHandler);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MEM_DS_TOOL_ERROR_CREATING_LOG_HANDLER.get(
                  logFile.getAbsolutePath(),
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    return serverConfig;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> exampleUsages =
         new LinkedHashMap<String[],String>(2);

    final String[] example1Args =
    {
      "--baseDN", "dc=example,dc=com"
    };
    exampleUsages.put(example1Args, INFO_MEM_DS_TOOL_EXAMPLE_1.get());

    final String[] example2Args =
    {
      "--baseDN", "dc=example,dc=com",
      "--port", "1389",
      "--ldifFile", "test.ldif",
      "--logFile", "log.txt",
      "--useDefaultSchema"
    };
    exampleUsages.put(example2Args, INFO_MEM_DS_TOOL_EXAMPLE_2.get());

    return exampleUsages;
  }
}
