/*
 * Copyright 2009 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009 UnboundID Corp.
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
import java.io.FileWriter;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Iterator;
import java.util.TreeMap;
import java.util.TreeSet;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.schema.AttributeTypeDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassDefinition;
import com.unboundid.ldap.sdk.schema.ObjectClassType;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.LDAPCommandLineTool;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.persist.PersistMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a tool which can be used to generate source code for a
 * Java class file based on information read from the schema of an LDAP
 * directory server.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class GenerateSourceFromSchema
       extends LDAPCommandLineTool
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3488976364950590266L;



  // Arguments used by this tool.
  private DNArgument     defaultParentDNArg;
  private FileArgument   outputDirectoryArg;
  private StringArgument auxiliaryClassArg;
  private StringArgument classNameArg;
  private StringArgument packageNameArg;
  private StringArgument rdnAttributeArg;
  private StringArgument structuralClassArg;

  // Indicates whether any date attributes have been identified, and therefore
  // we need to include java.util.Date in the import list.
  private boolean needDate;



  /**
   * Parse the provided command line arguments and perform the appropriate
   * processing.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(final String[] args)
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
  public static ResultCode main(final String[] args,
                                final OutputStream outStream,
                                final OutputStream errStream)
  {
    final GenerateSourceFromSchema tool =
         new GenerateSourceFromSchema(outStream, errStream);
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
  public GenerateSourceFromSchema(final OutputStream outStream,
                                  final OutputStream errStream)
  {
    super(outStream, errStream);

    needDate = false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolName()
  {
    return "generate-source-from-schema";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getToolDescription()
  {
    return INFO_GEN_SOURCE_TOOL_DESCRIPTION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addNonLDAPArguments(final ArgumentParser parser)
         throws ArgumentException
  {
    outputDirectoryArg = new FileArgument('d', "outputDirectory", false, 1,
         INFO_GEN_SOURCE_VALUE_PLACEHOLDER_PATH.get(),
         INFO_GEN_SOURCE_ARG_DESCRIPTION_OUTPUT_DIRECTORY.get(), true, true,
         false, true);
    parser.addArgument(outputDirectoryArg);

    structuralClassArg = new StringArgument('s', "structuralClass", true, 1,
         INFO_GEN_SOURCE_VALUE_PLACEHOLDER_NAME.get(),
         INFO_GEN_SOURCE_ARG_DESCRIPTION_STRUCTURAL_CLASS.get());
    parser.addArgument(structuralClassArg);

    auxiliaryClassArg = new StringArgument('a', "auxiliaryClass", false, 0,
         INFO_GEN_SOURCE_VALUE_PLACEHOLDER_NAME.get(),
         INFO_GEN_SOURCE_ARG_DESCRIPTION_AUXILIARY_CLASS.get());
    parser.addArgument(auxiliaryClassArg);

    rdnAttributeArg = new StringArgument('r', "rdnAttribute", true, 0,
         INFO_GEN_SOURCE_VALUE_PLACEHOLDER_NAME.get(),
         INFO_GEN_SOURCE_ARG_DESCRIPTION_RDN_ATTRIBUTE.get());
    parser.addArgument(rdnAttributeArg);

    defaultParentDNArg = new DNArgument('b', "defaultParentDN", false, 1,
         INFO_GEN_SOURCE_VALUE_PLACEHOLDER_DN.get(),
         INFO_GEN_SOURCE_ARG_DESCRIPTION_DEFAULT_PARENT_DN.get());
    parser.addArgument(defaultParentDNArg);

    packageNameArg = new StringArgument('n', "packageName", false, 1,
         INFO_GEN_SOURCE_VALUE_PLACEHOLDER_NAME.get(),
         INFO_GEN_SOURCE_ARG_DESCRIPTION_PACKAGE_NAME.get());
    parser.addArgument(packageNameArg);

    classNameArg = new StringArgument('c', "className", false, 1,
         INFO_GEN_SOURCE_VALUE_PLACEHOLDER_NAME.get(),
         INFO_GEN_SOURCE_ARG_DESCRIPTION_CLASS_NAME.get());
    parser.addArgument(classNameArg);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ResultCode doToolProcessing()
  {
    // Establish a connection to the target directory server and retrieve the
    // schema.
    final LDAPConnection conn;
    try
    {
      conn = getConnection();
    }
    catch (LDAPException le)
    {
      debugException(le);
      err(ERR_GEN_SOURCE_CANNOT_CONNECT.get(getExceptionMessage(le)));
      return le.getResultCode();
    }

    final Schema schema;
    try
    {
      schema = conn.getSchema();
      if (schema == null)
      {
        err(ERR_GEN_SOURCE_CANNOT_READ_SCHEMA.get(
             ERR_GEN_SOURCE_SCHEMA_NOT_RETURNED.get()));
        return ResultCode.NO_RESULTS_RETURNED;
      }
    }
    catch (LDAPException le)
    {
      debugException(le);
      err(ERR_GEN_SOURCE_CANNOT_READ_SCHEMA.get(getExceptionMessage(le)));
      return le.getResultCode();
    }
    finally
    {
      conn.close();
    }

    return generateSourceFile(schema);
  }



  /**
   * Generates the source file using the information in the provided schema.
   *
   * @param  schema  The schema to use to generate the source file.
   *
   * @return  A result code obtained for the processing.
   */
  ResultCode generateSourceFile(final Schema schema)
  {
    // Retrieve and process the structural object class.
    final TreeMap<String,AttributeTypeDefinition> requiredAttrs =
         new TreeMap<String,AttributeTypeDefinition>();
    final TreeMap<String,AttributeTypeDefinition> optionalAttrs =
         new TreeMap<String,AttributeTypeDefinition>();
    final TreeMap<String,TreeSet<String>> requiredAttrOCs =
         new TreeMap<String,TreeSet<String>>();
    final TreeMap<String,TreeSet<String>> optionalAttrOCs =
         new TreeMap<String,TreeSet<String>>();
    final TreeMap<String,String> types = new TreeMap<String,String>();

    final String structuralClassName = structuralClassArg.getValue();
    final ObjectClassDefinition structuralOC =
         schema.getObjectClass(structuralClassName);
    if (structuralOC == null)
    {
      err(ERR_GEN_SOURCE_STRUCTURAL_CLASS_NOT_FOUND.get(structuralClassName));
      return ResultCode.PARAM_ERROR;
    }

    if (structuralOC.getObjectClassType(schema) != ObjectClassType.STRUCTURAL)
    {
      err(ERR_GEN_SOURCE_STRUCTURAL_CLASS_NOT_STRUCTURAL.get(
           structuralClassName));
      return ResultCode.PARAM_ERROR;
    }

    processObjectClass(structuralOC, schema, requiredAttrs, requiredAttrOCs,
         optionalAttrs, optionalAttrOCs, types);


    // Retrieve and process the auxiliary object classes.
    final TreeMap<String,ObjectClassDefinition> auxiliaryOCs =
         new TreeMap<String,ObjectClassDefinition>();
    if (auxiliaryClassArg.isPresent())
    {
      for (final String s : auxiliaryClassArg.getValues())
      {
        final ObjectClassDefinition oc = schema.getObjectClass(s);
        if (oc == null)
        {
          err(ERR_GEN_SOURCE_AUXILIARY_CLASS_NOT_FOUND.get(s));
          return ResultCode.PARAM_ERROR;
        }

        if  (oc.getObjectClassType(schema) != ObjectClassType.AUXILIARY)
        {
          err(ERR_GEN_SOURCE_AUXILIARY_CLASS_NOT_AUXILIARY.get(s));
          return ResultCode.PARAM_ERROR;
        }

        auxiliaryOCs.put(toLowerCase(s), oc);

        processObjectClass(oc, schema, requiredAttrs, requiredAttrOCs,
             optionalAttrs, optionalAttrOCs, types);
      }
    }


    // Make sure all of the configured RDN attributes are associated with the
    // object classes.
    final TreeSet<String> rdnAttrs = new TreeSet<String>();
    for (final String s : rdnAttributeArg.getValues())
    {
      final AttributeTypeDefinition d = schema.getAttributeType(s);
      if (s == null)
      {
        err(ERR_GEN_SOURCE_RDN_ATTRIBUTE_NOT_DEFINED.get(s));
        return ResultCode.PARAM_ERROR;
      }

      final String lowerName = toLowerCase(d.getNameOrOID());
      rdnAttrs.add(lowerName);
      if (requiredAttrs.containsKey(lowerName))
      {
        // No action required.
      }
      else if (optionalAttrs.containsKey(lowerName))
      {
        // Move the attribute to the required set.
        requiredAttrs.put(lowerName, optionalAttrs.remove(lowerName));
        requiredAttrOCs.put(lowerName, optionalAttrOCs.remove(lowerName));
      }
      else
      {
        err(ERR_GEN_SOURCE_RDN_ATTRIBUTE_NOT_DEFINED.get(s));
        return ResultCode.PARAM_ERROR;
      }
    }


    final String className;
    if (classNameArg.isPresent())
    {
      className = classNameArg.getValue();
      final StringBuilder invalidReason = new StringBuilder();
      if (! PersistUtils.isValidJavaIdentifier(className, invalidReason))
      {
        err(ERR_GEN_SOURCE_INVALID_CLASS_NAME.get(className,
             invalidReason.toString()));
        return ResultCode.PARAM_ERROR;
      }
    }
    else
    {
      className =
           capitalize(PersistUtils.toJavaIdentifier(structuralClassName));
    }


    final File sourceFile = new File(outputDirectoryArg.getValue(),
         className + ".java");
    final PrintWriter writer;
    try
    {
      writer = new PrintWriter(new FileWriter(sourceFile));
    }
    catch (Exception e)
    {
      debugException(e);
      err(ERR_GEN_SOURCE_CANNOT_CREATE_WRITER.get(sourceFile.getAbsolutePath(),
           getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }


    if (packageNameArg.isPresent())
    {
      final String packageName = packageNameArg.getValue();
      if (packageName.length() > 0)
      {
        writer.println("package " + packageName + ';');
        writer.println();
        writer.println();
        writer.println();
      }
    }

    if (needDate)
    {
      writer.println("import " + Date.class.getName() + ';');
      writer.println();
    }

    writer.println("import " + Entry.class.getName() + ';');
    writer.println("import " + ReadOnlyEntry.class.getName() + ';');
    writer.println("import " + FilterUsage.class.getName() + ';');
    writer.println("import " + LDAPEntryField.class.getName() + ';');
    writer.println("import " + LDAPField.class.getName() + ';');
    writer.println("import " + LDAPObject.class.getName() + ';');
    writer.println("import " + LDAPPersistException.class.getName() + ';');
    writer.println();
    writer.println();
    writer.println();
    writer.println("/**");
    writer.println(" * This class was generated by the " + getToolName() +
         " tool");
    writer.println(" * provided with the UnboundID LDAP SDK for Java.  It " +
         "may be customized as");
    writer.println(" * desired to better suit your needs.");
    writer.println(" */");
    writer.println("@LDAPObject(structuralClass=\"" + structuralClassName +
         "\",");

    switch (auxiliaryOCs.size())
    {
      case 0:
        // No action required.
        break;

      case 1:
        writer.println("            auxiliaryClass=\"" +
             auxiliaryOCs.values().iterator().next().getNameOrOID() + "\",");
        break;

      default:
        final Iterator<ObjectClassDefinition> iterator =
             auxiliaryOCs.values().iterator();
        writer.println("            auxiliaryClass={ \"" +
             iterator.next().getNameOrOID() + "\",");
        while (iterator.hasNext())
        {
          final String ocName = iterator.next().getNameOrOID();
          if (iterator.hasNext())
          {
            writer.println("                             \"" + ocName +
                 "\",");
          }
          else
          {
            writer.println("                             \"" + ocName +
                 "\" },");
          }
        }
        break;
    }

    if (defaultParentDNArg.isPresent())
    {
      writer.println("            defaultParentDN=\"" +
           defaultParentDNArg.getValue() + "\",");
    }

    writer.println("            postDecodeMethod=\"doPostDecode\",");
    writer.println("            postEncodeMethod=\"doPostEncode\")");
    writer.println("public class " + className);
    writer.println("{");
    writer.println("  // The field to use to hold a read-only copy of the " +
         "associated entry.");
    writer.println("  @LDAPEntryField()");
    writer.println("  private ReadOnlyEntry ldapEntry;");


    // Add all of the fields.  First the fields for the RDN attributes, then
    // for the rest of the required attributes, and then for the optional
    // attributes.
    for (final String lowerName : rdnAttrs)
    {
      final AttributeTypeDefinition d = requiredAttrs.get(lowerName);
      final TreeSet<String> ocNames = requiredAttrOCs.get(lowerName);
      writeField(schema, writer, d, types.get(lowerName), ocNames, true, true);
    }

    for (final String lowerName : requiredAttrs.keySet())
    {
      if (rdnAttrs.contains(lowerName))
      {
        continue;
      }

      final AttributeTypeDefinition d = requiredAttrs.get(lowerName);
      final TreeSet<String> ocNames = requiredAttrOCs.get(lowerName);
      writeField(schema, writer, d, types.get(lowerName), ocNames, false, true);
    }

    for (final String lowerName : optionalAttrs.keySet())
    {
      final AttributeTypeDefinition d = optionalAttrs.get(lowerName);
      final TreeSet<String> ocNames = optionalAttrOCs.get(lowerName);
      writeField(schema, writer, d, types.get(lowerName), ocNames, false,
           false);
    }


    // Add the constructor.
    writer.println();
    writer.println();
    writer.println();
    writer.println("  /**");
    writer.println("   * Creates a new instance of this object.  All fields " +
         "will be uninitialized,");
    writer.println("   * so the setter methods should be used to assign " +
         "values to them.");
    writer.println("   */");
    writer.println("  public " + className + "()");
    writer.println("  {");
    writer.println("    // No initialization will be performed by default.  " +
         "Note that if you set");
    writer.println("    // values for any fields marked with an @LDAPField, " +
         "@LDAPDNField, or");
    writer.println("    // @LDAPEntryField annotation, they will be " +
         "overwritten in the course of");
    writer.println("    // decoding initializing this object from an LDAP " +
         "entry.");
    writer.println("  }");


    // Add the post-decode and post-encode methods.
    writer.println();
    writer.println();
    writer.println();
    writer.println("  /**");
    writer.println("   * Performs any processing that may be necessary after " +
         "initializing this");
    writer.println("   * object from an LDAP entry.");
    writer.println("   *");
    writer.println("   * @throws  LDAPPersistException  If the generated " +
         "entry should not be used.");
    writer.println("   */");
    writer.println("  private void doPostDecode()");
    writer.println("          throws LDAPPersistException");
    writer.println("  {");
    writer.println("    // No processing is needed by default.  You may " +
         "provide an implementation");
    writer.println("    // for this method if custom post-decode processing " +
         "is needed.");
    writer.println("  }");
    writer.println();
    writer.println();
    writer.println();
    writer.println("  /**");
    writer.println("   * Performs any processing that may be necessary after " +
         "encoding this object");
    writer.println("   * to an LDAP entry.");
    writer.println("   *");
    writer.println("   * @param  entry  The entry that has been generated.  " +
         "It may be altered if");
    writer.println("   *                desired.");    writer.println("   *");
    writer.println("   * @throws  LDAPPersistException  If there is a " +
         "problem with the object after");
    writer.println("   *                                it has been decoded " +
         "from an LDAP entry.");
    writer.println("   */");
    writer.println("  private void doPostEncode(final Entry entry)");
    writer.println("          throws LDAPPersistException");
    writer.println("  {");
    writer.println("    // No processing is needed by default.  You may " +
         "provide an implementation");
    writer.println("    // for this method if custom post-encode processing " +
         "is needed.");
    writer.println("  }");


    // Add a method for getting a read-only copy of the associated entry.
    writer.println();
    writer.println();
    writer.println();
    writer.println("  /**");
    writer.println("   * Retrieves a read-only copy of the entry with which " +
         "this object is");
    writer.println("   * associated, if it is available.  It will only be " +
         "available if this object");
    writer.println("   * was decoded from or encoded to an LDAP entry.");
    writer.println("   *");
    writer.println("   * @return  A read-only copy of the entry with which " +
         "this object is");
    writer.println("   *          associated, or {@code null} if it is not " +
         "available.");
    writer.println("   */");
    writer.println("  public ReadOnlyEntry getLDAPEntry()");
    writer.println("  {");
    writer.println("    return ldapEntry;");
    writer.println("  }");


    // Add a method for getting the DN of the associated entry.
    writer.println();
    writer.println();
    writer.println();
    writer.println("  /**");
    writer.println("   * Retrieves the DN of the entry with which this " +
         "object is associated, if it");
    writer.println("   * is available.  It will only be available if this " +
         "object was decoded from or");
    writer.println("   * encoded to an LDAP entry.");
    writer.println("   *");
    writer.println("   * @return  The DN of the entry with which this object " +
         "is associated, or");
    writer.println("   *          {@code null} if it is not available.");
    writer.println("   */");
    writer.println("  public String getLDAPEntryDN()");
    writer.println("  {");
    writer.println("    if (ldapEntry == null)");
    writer.println("    {");
    writer.println("      return null;");
    writer.println("    }");
    writer.println("    else");
    writer.println("    {");
    writer.println("      return ldapEntry.getDN();");
    writer.println("    }");
    writer.println("  }");


    // Add getter and setter methods for all of the fields associated with LDAP
    // attributes.  First the fields for the RDN attributes, then for the rest
    // of the required attributes, and then for the optional attributes.
    for (final String lowerName : rdnAttrs)
    {
      final AttributeTypeDefinition d = requiredAttrs.get(lowerName);
      writeGetterAndSetter(writer, d, types.get(lowerName));
    }

    for (final String lowerName : requiredAttrs.keySet())
    {
      if (rdnAttrs.contains(lowerName))
      {
        continue;
      }

      final AttributeTypeDefinition d = requiredAttrs.get(lowerName);
      writeGetterAndSetter(writer, d, types.get(lowerName));
    }

    for (final String lowerName : optionalAttrs.keySet())
    {
      final AttributeTypeDefinition d = optionalAttrs.get(lowerName);
      writeGetterAndSetter(writer, d, types.get(lowerName));
    }

    writer.println("}");
    writer.println();
    writer.close();

    return ResultCode.SUCCESS;
  }





  /**
   * Performs an appropriate set of processing for the provided object class to
   * ensure that all of the required and optional attributes are classified
   * properly.
   *
   * @param  oc   The object class to process.
   * @param  s    The server schema.
   * @param  ra   The set of required attributes identified so far.
   * @param  rac  The object classes referenced by the required attributes.
   * @param  oa   The set of optional attributes identified so far.
   * @param  oac  The object classes referenced by the optional attributes.
   * @param  t    A map of attribute type names to Java types.
   */
  void processObjectClass(final ObjectClassDefinition oc, final Schema s,
            final TreeMap<String,AttributeTypeDefinition> ra,
            final TreeMap<String,TreeSet<String>> rac,
            final TreeMap<String,AttributeTypeDefinition> oa,
            final TreeMap<String,TreeSet<String>> oac,
            final TreeMap<String,String> t)
  {
    for (final AttributeTypeDefinition d : oc.getRequiredAttributes(s, true))
    {
      if (d.hasNameOrOID("objectClass"))
      {
        continue;
      }

      final String lowerName = toLowerCase(d.getNameOrOID());
      if (ra.containsKey(lowerName))
      {
        rac.get(lowerName).add(oc.getNameOrOID());
      }
      else if (oa.containsKey(lowerName))
      {
        oa.remove(lowerName);
        ra.put(lowerName, d);

        final TreeSet<String> ocSet = oac.remove(lowerName);
        ocSet.add(oc.getNameOrOID());
        rac.put(lowerName, ocSet);
      }
      else
      {
        final TreeSet<String> ocSet = new TreeSet<String>();
        ocSet.add(oc.getNameOrOID());
        ra.put(lowerName, d);
        rac.put(lowerName, ocSet);
        t.put(lowerName, getJavaType(s, d));
      }
    }

    for (final AttributeTypeDefinition d : oc.getOptionalAttributes(s, true))
    {
      if (d.hasNameOrOID("objectClass"))
      {
        continue;
      }

      final String lowerName = toLowerCase(d.getNameOrOID());
      if (ra.containsKey(lowerName))
      {
        rac.get(lowerName).add(oc.getNameOrOID());
      }
      else if (oa.containsKey(lowerName))
      {
        oac.get(lowerName).add(oc.getNameOrOID());
      }
      else
      {
        final TreeSet<String> ocSet = new TreeSet<String>();
        ocSet.add(oc.getNameOrOID());
        oa.put(lowerName, d);
        oac.put(lowerName, ocSet);
        t.put(lowerName, getJavaType(s, d));
      }
    }
  }



  /**
   * Writes information about a field to the Java class file.
   *
   * @param  schema    The schema from which the attribute type was read.
   * @param  writer    The writer to which the field information should be
   *                   written.
   * @param  d         The attribute type definition.
   * @param  type      The name of the Java type to use for the field.
   * @param  ocNames   The names of the object classes for the attribute type.
   * @param  inRDN     Indicates whether the attribute should be included in
   *                   generated entry RDNs.
   * @param  required  Indicates whether the attribute should be considered
   *                   required.
   */
  static void writeField(final Schema schema, final PrintWriter writer,
                         final AttributeTypeDefinition d, final String type,
                         final TreeSet<String> ocNames,
                         final boolean inRDN, final boolean required)
  {
    final String attrName  = d.getNameOrOID();

    writer.println();

    if (inRDN)
    {
      writer.println("  // The field used for RDN attribute " + attrName + '.');
    }
    else if (required)
    {
      writer.println("  // The field used for required attribute " + attrName +
           '.');
    }
    else
    {
      writer.println("  // The field used for optional attribute " + attrName +
           '.');
    }

    writer.println("  @LDAPField(attribute=\"" + attrName + "\",");

    if (ocNames.size() == 1)
    {
      writer.print("             objectClass=\"" + ocNames.iterator().next() +
           '"');
    }
    else
    {
      final Iterator<String> iterator = ocNames.iterator();
      writer.println("             objectClass={ \"" +
           iterator.next() + "\",");

      while (iterator.hasNext())
      {
        final String name = iterator.next();
        if (iterator.hasNext())
        {
          writer.println("                           \"" + name + "\",");
        }
        else
        {
          writer.print("                           \"" + name + "\" }");
        }
      }
    }

    if (inRDN)
    {
      writer.println(",");
      writer.println("             inRDN=true,");
      writer.print("             filterUsage=FilterUsage.ALWAYS_ALLOWED");
    }
    else
    {
      writer.println(",");
      writer.print("             " +
           "filterUsage=FilterUsage.CONDITIONALLY_ALLOWED");
    }

    if (required)
    {
      writer.println(",");
      writer.print("             requiredForEncode=true");
    }

    writer.println(")");
    if (d.isSingleValued())
    {
      writer.println("  private " + type + ' ' +
                     PersistUtils.toJavaIdentifier(attrName) + ';');
    }
    else
    {
      writer.println("  private " + type + "[] " +
                     PersistUtils.toJavaIdentifier(attrName) + ';');
    }
  }



  /**
   * Writes getter and setter methods for the provided attribute.
   *
   * @param  writer  The writer to use to write the methods.
   * @param  d       The attribute type definition to be written.
   * @param  type    The name of the Java type to use for the attribute.
   */
  static void writeGetterAndSetter(final PrintWriter writer,
                                   final AttributeTypeDefinition d,
                                   final String type)
  {
    writer.println();
    writer.println();
    writer.println();

    final String attrName  = d.getNameOrOID();
    final String fieldName = PersistUtils.toJavaIdentifier(attrName);
    final String capFieldName = capitalize(fieldName);

    if (d.isSingleValued())
    {
      writer.println("  /**");
      writer.println("   * Retrieves the value for the field associated with " +
           "the");
      writer.println("   * " + attrName + " attribute, if defined.");
      writer.println("   *");
      writer.println("   * @return  The value for the field associated with " +
           "the");
      writer.println("   *          " + attrName + " attribute, or");
      writer.println("   *          {@code null} if it is not defined.");
      writer.println("   */");
      writer.println("  public " + type + " get" + capFieldName + "()");
      writer.println("  {");
      writer.println("    return " + fieldName + ';');
      writer.println("  }");
      writer.println();
      writer.println();
      writer.println();
      writer.println("  /**");
      writer.println("   * Sets the value for the field associated with the");
      writer.println("   * " + attrName + " attribute.");
      writer.println("   *");
      writer.println("   * @param  v  The value for the field associated " +
            "with the");
      writer.println("   *            " + attrName + " attribute.");
      writer.println("   */");
      writer.println("  public void set" + capFieldName + "(final " + type +
           " v)");
      writer.println("  {");
      writer.println("    this." + fieldName + " = v;");
      writer.println("  }");
    }
    else
    {
      writer.println("  /**");
      writer.println("   * Retrieves the values for the field associated " +
           "with the");
      writer.println("   * " + attrName + " attribute, if defined.");
      writer.println("   *");
      writer.println("   * @return  The values for the field associated with " +
           "the");
      writer.println("   *          " + attrName + " attribute, or");
      writer.println("   *          {@code null} if it is not defined.");
      writer.println("   */");
      writer.println("  public " + type + "[] get" + capFieldName + "()");
      writer.println("  {");
      writer.println("    return " + fieldName + ';');
      writer.println("  }");
      writer.println();
      writer.println();
      writer.println();
      writer.println("  /**");
      writer.println("   * Sets the values for the field associated with the");
      writer.println("   * " + attrName + " attribute.");
      writer.println("   *");
      writer.println("   * @param  v  The values for the field associated " +
           "with the");
      writer.println("   *            " + attrName + " attribute.");
      writer.println("   */");
      writer.println("  public void set" + capFieldName + "(final " + type +
           "... v)");
      writer.println("  {");
      writer.println("    this." + fieldName + " = v;");
      writer.println("  }");
    }
  }



  /**
   * Retrieves the Java type to use for the provided attribute type definition.
   * For multi-valued attributes, the value returned will be the base type
   * without square brackets to indicate an array.
   *
   * @param  schema  The schema to use to determine the syntax for the
   *                 attribute.
   * @param  d       The attribute type definition for which to get the Java
   *                 type.
   *
   * @return  The Java type to use for the provided attribute type definition.
   */
  String getJavaType(final Schema schema, final AttributeTypeDefinition d)
  {
    final String syntaxOID = d.getSyntaxOID(schema);
    if (syntaxOID == null)
    {
      return "String";
    }

    final String oid;
    final int bracePos = syntaxOID.indexOf('{');
    if (bracePos > 0)
    {
      oid = syntaxOID.substring(0, bracePos);
    }
    else
    {
      oid = syntaxOID;
    }

    if (oid.equals("1.3.6.1.4.1.1466.115.121.1.7"))
    {
      // Boolean
      return "Boolean";
    }
    else if (oid.equals("1.3.6.1.4.1.4203.1.1.2") ||
             oid.equals("1.3.6.1.4.1.1466.115.121.1.5") ||
             oid.equals("1.3.6.1.4.1.1466.115.121.1.8") ||
             oid.equals("1.3.6.1.4.1.1466.115.121.1.9") ||
             oid.equals("1.3.6.1.4.1.1466.115.121.1.10") ||
             oid.equals("1.3.6.1.4.1.1466.115.121.1.28") ||
             oid.equals("1.3.6.1.4.1.1466.115.121.1.40"))
    {
      // auth password
      // binary
      // certificate
      // certificate list
      // certificate pair
      // JPEG
      // octet string
      return "byte[]";
    }
    else if (oid.equals("1.3.6.1.4.1.1466.115.121.1.24"))
    {
      // generalized time.
      needDate = true;
      return "Date";
    }
    else if (oid.equals("1.3.6.1.4.1.1466.115.121.1.27"))
    {
      // integer
      return "Long";
    }
    else
    {
      return "String";
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<String[],String>(1);

    final String[] args =
    {
      "--hostname", "server.example.com",
      "--port", "389",
      "--bindDN", "uid=admin,dc=example,dc=com",
      "--bindPassword", "password",
      "--outputDirectory", "src/com/example",
      "--structuralClass", "myStructuralClass",
      "--auxiliaryClass", "auxClass1",
      "--auxiliaryClass", "auxClass2",
      "--rdnAttribute", "cn",
      "--defaultParentDN", "dc=example,dc=com",
      "--packageName", "com.example",
      "--className", "MyObject"
    };
    examples.put(args, INFO_GEN_SOURCE_EXAMPLE_1.get());

    return examples;
  }
}
