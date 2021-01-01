/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.persist;



import java.io.File;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFRecord;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;



/**
 * This class provides a tool which can be used to generate LDAP attribute
 * type and object class definitions which may be used to store objects
 * created from a specified Java class.  The given class must be included in the
 * classpath of the JVM used to invoke the tool, and must be marked with the
 * {@link LDAPObject} annotation.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class GenerateSchemaFromSource
       extends CommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1029934829295836935L;



  // Arguments used by this tool.
  @Nullable private BooleanArgument modifyFormatArg;
  @Nullable private FileArgument    outputFileArg;
  @Nullable private StringArgument  classNameArg;



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
    final GenerateSchemaFromSource tool =
         new GenerateSchemaFromSource(outStream, errStream);
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
  public GenerateSchemaFromSource(@Nullable final OutputStream outStream,
                                  @Nullable final OutputStream errStream)
  {
    super(outStream, errStream);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "generate-schema-from-source";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_GEN_SCHEMA_TOOL_DESCRIPTION.get();
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
   * {@inheritDoc}
   */
  @Override()
  public void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    classNameArg = new StringArgument('c', "javaClass", true, 1,
         INFO_GEN_SCHEMA_VALUE_PLACEHOLDER_CLASS.get(),
         INFO_GEN_SCHEMA_ARG_DESCRIPTION_JAVA_CLASS.get());
    classNameArg.addLongIdentifier("java-class", true);
    parser.addArgument(classNameArg);

    outputFileArg = new FileArgument('f', "outputFile", true, 1,
         INFO_GEN_SCHEMA_VALUE_PLACEHOLDER_PATH.get(),
         INFO_GEN_SCHEMA_ARG_DESCRIPTION_OUTPUT_FILE.get(), false, true, true,
         false);
    outputFileArg.addLongIdentifier("output-file", true);
    parser.addArgument(outputFileArg);

    modifyFormatArg = new BooleanArgument('m', "modifyFormat",
         INFO_GEN_SCHEMA_ARG_DESCRIPTION_MODIFY_FORMAT.get());
    modifyFormatArg.addLongIdentifier("modify-format", true);
    parser.addArgument(modifyFormatArg);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Load the specified Java class.
    final String className = classNameArg.getValue();
    final Class<?> targetClass;
    try
    {
      targetClass = Class.forName(className);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      err(ERR_GEN_SCHEMA_CANNOT_LOAD_CLASS.get(className));
      return ResultCode.PARAM_ERROR;
    }


    // Create an LDAP persister for the class and use it to ensure that the
    // class is valid.
    final LDAPPersister<?> persister;
    try
    {
      persister = LDAPPersister.getInstance(targetClass);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      err(ERR_GEN_SCHEMA_INVALID_CLASS.get(className,
           StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }


    // Use the persister to generate the attribute type and object class
    // definitions.
    final List<AttributeTypeDefinition> attrTypes;
    try
    {
      attrTypes = persister.constructAttributeTypes();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      err(ERR_GEN_SCHEMA_ERROR_CONSTRUCTING_ATTRS.get(className,
           StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }

    final List<ObjectClassDefinition> objectClasses;
    try
    {
      objectClasses = persister.constructObjectClasses();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      err(ERR_GEN_SCHEMA_ERROR_CONSTRUCTING_OCS.get(className,
           StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }


    // Convert the attribute type and object class definitions into their
    // appropriate string representations.
    int i=0;
    final ASN1OctetString[] attrTypeValues =
         new ASN1OctetString[attrTypes.size()];
    for (final AttributeTypeDefinition d : attrTypes)
    {
      attrTypeValues[i++] = new ASN1OctetString(d.toString());
    }

    i=0;
    final ASN1OctetString[] ocValues =
         new ASN1OctetString[objectClasses.size()];
    for (final ObjectClassDefinition d : objectClasses)
    {
      ocValues[i++] = new ASN1OctetString(d.toString());
    }


    // Construct the LDIF record to be written.
    final LDIFRecord schemaRecord;
    if (modifyFormatArg.isPresent())
    {
      schemaRecord = new LDIFModifyChangeRecord("cn=schema",
           new Modification(ModificationType.ADD, "attributeTypes",
                attrTypeValues),
           new Modification(ModificationType.ADD, "objectClasses", ocValues));
    }
    else
    {
      schemaRecord = new Entry("cn=schema",
           new Attribute("objectClass", "top", "ldapSubentry", "subschema"),
           new Attribute("cn", "schema"),
           new Attribute("attributeTypes", attrTypeValues),
           new Attribute("objectClasses", ocValues));
    }


    // Write the schema entry to the specified file.
    final File outputFile = outputFileArg.getValue();
    try
    {
      final LDIFWriter ldifWriter = new LDIFWriter(outputFile);
      ldifWriter.writeLDIFRecord(schemaRecord);
      ldifWriter.close();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      err(ERR_GEN_SCHEMA_CANNOT_WRITE_SCHEMA.get(outputFile.getAbsolutePath(),
           StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }


    return ResultCode.SUCCESS;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));

    final String[] args =
    {
      "--javaClass", "com.example.MyClass",
      "--outputFile", "MyClass-schema.ldif"
    };
    examples.put(args, INFO_GEN_SCHEMA_EXAMPLE_1.get());

    return examples;
  }
}
