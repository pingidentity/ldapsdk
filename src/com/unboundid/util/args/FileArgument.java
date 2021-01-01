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
package com.unboundid.util.args;



import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class defines an argument that is intended to hold values which refer to
 * files on the local filesystem.  File arguments must take values, and it is
 * possible to restrict the values to files that exist, or whose parent exists.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class FileArgument
       extends Argument
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8478637530068695898L;



  // Indicates whether values must represent files that exist.
  private final boolean fileMustExist;

  // Indicates whether the provided value must be a directory if it exists.
  private final boolean mustBeDirectory;

  // Indicates whether the provided value must be a regular file if it exists.
  private final boolean mustBeFile;

  // Indicates whether values must represent files with parent directories that
  // exist.
  private final boolean parentMustExist;

  // The set of values assigned to this argument.
  @NotNull private final ArrayList<File> values;

  // The path to the directory that will serve as the base directory for
  // relative paths.
  @Nullable private File relativeBaseDirectory;

  // The argument value validators that have been registered for this argument.
  @NotNull private final List<ArgumentValueValidator> validators;

  // The list of default values for this argument.
  @Nullable private final List<File> defaultValues;



  /**
   * Creates a new file argument with the provided information.  It will not
   * be required, will permit at most one occurrence, will use a default
   * placeholder, will not have any default values, and will not impose any
   * constraints on the kinds of values it can have.
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
  public FileArgument(@Nullable final Character shortIdentifier,
                      @Nullable final String longIdentifier,
                      @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, false, 1, null, description);
  }



  /**
   * Creates a new file argument with the provided information.  There will not
   * be any default values or constraints on the kinds of values it can have.
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
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public FileArgument(@Nullable final Character shortIdentifier,
                      @Nullable final String longIdentifier,
                      final boolean isRequired, final int maxOccurrences,
                      @Nullable final String valuePlaceholder,
                      @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         valuePlaceholder, description, false, false, false, false, null);
  }



  /**
   * Creates a new file argument with the provided information.  It will not
   * have any default values.
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
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  fileMustExist     Indicates whether each value must refer to a file
   *                           that exists.
   * @param  parentMustExist   Indicates whether each value must refer to a file
   *                           whose parent directory exists.
   * @param  mustBeFile        Indicates whether each value must refer to a
   *                           regular file, if it exists.
   * @param  mustBeDirectory   Indicates whether each value must refer to a
   *                           directory, if it exists.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public FileArgument(@Nullable final Character shortIdentifier,
                      @Nullable final String longIdentifier,
                      final boolean isRequired, final int maxOccurrences,
                      @Nullable final String valuePlaceholder,
                      @NotNull final String description,
                      final boolean fileMustExist,
                      final boolean parentMustExist, final boolean mustBeFile,
                      final boolean mustBeDirectory)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired, maxOccurrences,
         valuePlaceholder, description, fileMustExist, parentMustExist,
         mustBeFile, mustBeDirectory, null);
  }



  /**
   * Creates a new file argument with the provided information.
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
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  fileMustExist     Indicates whether each value must refer to a file
   *                           that exists.
   * @param  parentMustExist   Indicates whether each value must refer to a file
   *                           whose parent directory exists.
   * @param  mustBeFile        Indicates whether each value must refer to a
   *                           regular file, if it exists.
   * @param  mustBeDirectory   Indicates whether each value must refer to a
   *                           directory, if it exists.
   * @param  defaultValues     The set of default values to use for this
   *                           argument if no values were provided.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public FileArgument(@Nullable final Character shortIdentifier,
                      @Nullable final String longIdentifier,
                      final boolean isRequired, final int maxOccurrences,
                      @Nullable final String valuePlaceholder,
                      @NotNull final String description,
                      final boolean fileMustExist,
                      final boolean parentMustExist, final boolean mustBeFile,
                      final boolean mustBeDirectory,
                      @Nullable final List<File> defaultValues)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         (valuePlaceholder == null)
              ? INFO_PLACEHOLDER_PATH.get()
              : valuePlaceholder,
         description);

    if (mustBeFile && mustBeDirectory)
    {
      throw new ArgumentException(ERR_FILE_CANNOT_BE_FILE_AND_DIRECTORY.get(
                                       getIdentifierString()));
    }

    this.fileMustExist   = fileMustExist;
    this.parentMustExist = parentMustExist;
    this.mustBeFile      = mustBeFile;
    this.mustBeDirectory = mustBeDirectory;

    if ((defaultValues == null) || defaultValues.isEmpty())
    {
      this.defaultValues = null;
    }
    else
    {
      this.defaultValues = Collections.unmodifiableList(defaultValues);
    }

    values                = new ArrayList<>(5);
    validators            = new ArrayList<>(5);
    relativeBaseDirectory = null;
  }



  /**
   * Creates a new file argument that is a "clean" copy of the provided source
   * argument.
   *
   * @param  source  The source argument to use for this argument.
   */
  private FileArgument(@NotNull final FileArgument source)
  {
    super(source);

    fileMustExist         = source.fileMustExist;
    mustBeDirectory       = source.mustBeDirectory;
    mustBeFile            = source.mustBeFile;
    parentMustExist       = source.parentMustExist;
    defaultValues         = source.defaultValues;
    relativeBaseDirectory = source.relativeBaseDirectory;
    validators            = new ArrayList<>(source.validators);
    values                = new ArrayList<>(5);
  }



  /**
   * Indicates whether each value must refer to a file that exists.
   *
   * @return  {@code true} if the target files must exist, or {@code false} if
   *          it is acceptable for values to refer to files that do not exist.
   */
  public boolean fileMustExist()
  {
    return fileMustExist;
  }



  /**
   * Indicates whether each value must refer to a file whose parent directory
   * exists.
   *
   * @return  {@code true} if the parent directory for target files must exist,
   *          or {@code false} if it is acceptable for values to refer to files
   *          whose parent directories do not exist.
   */
  public boolean parentMustExist()
  {
    return parentMustExist;
  }



  /**
   * Indicates whether each value must refer to a regular file (if it exists).
   *
   * @return  {@code true} if each value must refer to a regular file (if it
   *          exists), or {@code false} if it may refer to a directory.
   */
  public boolean mustBeFile()
  {
    return mustBeFile;
  }



  /**
   * Indicates whether each value must refer to a directory (if it exists).
   *
   * @return  {@code true} if each value must refer to a directory (if it
   *          exists), or {@code false} if it may refer to a regular file.
   */
  public boolean mustBeDirectory()
  {
    return mustBeDirectory;
  }



  /**
   * Retrieves the list of default values for this argument, which will be used
   * if no values were provided.
   *
   * @return   The list of default values for this argument, or {@code null} if
   *           there are no default values.
   */
  @Nullable()
  public List<File> getDefaultValues()
  {
    return defaultValues;
  }



  /**
   * Retrieves the directory that will serve as the base directory for relative
   * paths, if one has been defined.
   *
   * @return  The directory that will serve as the base directory for relative
   *          paths, or {@code null} if relative paths will be relative to the
   *          current working directory.
   */
  @Nullable()
  public File getRelativeBaseDirectory()
  {
    return relativeBaseDirectory;
  }



  /**
   * Specifies the directory that will serve as the base directory for relative
   * paths.
   *
   * @param  relativeBaseDirectory  The directory that will serve as the base
   *                                directory for relative paths.  It may be
   *                                {@code null} if relative paths should be
   *                                relative to the current working directory.
   */
  public void setRelativeBaseDirectory(
                   @Nullable final File relativeBaseDirectory)
  {
    this.relativeBaseDirectory = relativeBaseDirectory;
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
    // NOTE:  java.io.File has an extremely weird behavior.  When a File object
    // is created from a relative path and that path contains only the filename,
    // then calling getParent or getParentFile will return null even though it
    // obviously has a parent.  Therefore, you must always create a File using
    // the absolute path if you might want to get the parent.  Also, if the path
    // is relative, then we might want to control the base to which it is
    // relative.
    File f = new File(valueString);
    if (! f.isAbsolute())
    {
      if (relativeBaseDirectory == null)
      {
        f = new File(f.getAbsolutePath());
      }
      else
      {
        f = new File(new File(relativeBaseDirectory,
             valueString).getAbsolutePath());
      }
    }

    if (f.exists())
    {
      if (mustBeFile && (! f.isFile()))
      {
        throw new ArgumentException(ERR_FILE_VALUE_NOT_FILE.get(
                                         getIdentifierString(),
                                         f.getAbsolutePath()));
      }
      else if (mustBeDirectory && (! f.isDirectory()))
      {
        throw new ArgumentException(ERR_FILE_VALUE_NOT_DIRECTORY.get(
                                         getIdentifierString(),
                                         f.getAbsolutePath()));
      }
    }
    else
    {
      if (fileMustExist)
      {
        throw new ArgumentException(ERR_FILE_DOESNT_EXIST.get(
                                         f.getAbsolutePath(),
                                         getIdentifierString()));
      }
      else if (parentMustExist)
      {
        final File parentFile = f.getAbsoluteFile().getParentFile();
        if ((parentFile == null) ||
            (! parentFile.exists()) ||
            (! parentFile.isDirectory()))
        {
          throw new ArgumentException(ERR_FILE_PARENT_DOESNT_EXIST.get(
                                           f.getAbsolutePath(),
                                           getIdentifierString()));
        }
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

    values.add(f);
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
  public File getValue()
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
   * Retrieves the set of values for this argument.
   *
   * @return  The set of values for this argument.
   */
  @NotNull()
  public List<File> getValues()
  {
    if (values.isEmpty() && (defaultValues != null))
    {
      return defaultValues;
    }

    return Collections.unmodifiableList(values);
  }



  /**
   * Reads the contents of the file specified as the value to this argument and
   * retrieves a list of the lines contained in it.  If there are multiple
   * values for this argument, then the file specified as the first value will
   * be used.
   *
   * @return  A list containing the lines of the target file, or {@code null} if
   *          no values were provided.
   *
   * @throws  IOException  If the specified file does not exist or a problem
   *                       occurs while reading the contents of the file.
   */
  @Nullable()
  public List<String> getFileLines()
         throws IOException
  {
    final File f = getValue();
    if (f == null)
    {
      return null;
    }

    final ArrayList<String> lines  = new ArrayList<>(20);
    final BufferedReader    reader = new BufferedReader(new FileReader(f));
    try
    {
      String line = reader.readLine();
      while (line != null)
      {
        lines.add(line);
        line = reader.readLine();
      }
    }
    finally
    {
      reader.close();
    }

    return lines;
  }



  /**
   * Reads the contents of the file specified as the value to this argument and
   * retrieves a list of the non-blank lines contained in it.  If there are
   * multiple values for this argument, then the file specified as the first
   * value will be used.
   *
   * @return  A list containing the non-blank lines of the target file, or
   *          {@code null} if no values were provided.
   *
   * @throws  IOException  If the specified file does not exist or a problem
   *                       occurs while reading the contents of the file.
   */
  @Nullable()
  public List<String> getNonBlankFileLines()
         throws IOException
  {
    final File f = getValue();
    if (f == null)
    {
      return null;
    }

    final ArrayList<String> lines = new ArrayList<>(20);
    final BufferedReader reader = new BufferedReader(new FileReader(f));
    try
    {
      String line = reader.readLine();
      while (line != null)
      {
        if (! line.isEmpty())
        {
          lines.add(line);
        }
        line = reader.readLine();
      }
    }
    finally
    {
      reader.close();
    }

    return lines;
  }



  /**
   * Reads the contents of the file specified as the value to this argument.  If
   * there are multiple values for this argument, then the file specified as the
   * first value will be used.
   *
   * @return  A byte array containing the contents of the target file, or
   *          {@code null} if no values were provided.
   *
   * @throws  IOException  If the specified file does not exist or a problem
   *                       occurs while reading the contents of the file.
   */
  @Nullable()
  public byte[] getFileBytes()
         throws IOException
  {
    final File f = getValue();
    if (f == null)
    {
      return null;
    }

    final byte[] fileData = new byte[(int) f.length()];
    final FileInputStream inputStream = new FileInputStream(f);
    try
    {
      int startPos  = 0;
      int length    = fileData.length;
      int bytesRead = inputStream.read(fileData, startPos, length);
      while ((bytesRead > 0) && (startPos < fileData.length))
      {
        startPos += bytesRead;
        length   -= bytesRead;
        bytesRead = inputStream.read(fileData, startPos, length);
      }

      if (startPos < fileData.length)
      {
        throw new IOException(ERR_FILE_CANNOT_READ_FULLY.get(
                                   f.getAbsolutePath(), getIdentifierString()));
      }

      return fileData;
    }
    finally
    {
      inputStream.close();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getValueStringRepresentations(final boolean useDefault)
  {
    final List<File> files;
    if (values.isEmpty())
    {
      if (useDefault)
      {
        files = defaultValues;
      }
      else
      {
        return Collections.emptyList();
      }
    }
    else
    {
      files = values;
    }

    if ((files == null) || files.isEmpty())
    {
      return Collections.emptyList();
    }

    final ArrayList<String> valueStrings = new ArrayList<>(files.size());
    for (final File f : files)
    {
      valueStrings.add(f.getAbsolutePath());
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
    if (mustBeDirectory)
    {
      return INFO_FILE_TYPE_PATH_DIRECTORY.get();
    }
    else
    {
      return INFO_FILE_TYPE_PATH_FILE.get();
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getValueConstraints()
  {
    final StringBuilder buffer = new StringBuilder();

    if (mustBeDirectory)
    {
      if (fileMustExist)
      {
        buffer.append(INFO_FILE_CONSTRAINTS_DIR_MUST_EXIST.get());
      }
      else if (parentMustExist)
      {
        buffer.append(INFO_FILE_CONSTRAINTS_DIR_PARENT_MUST_EXIST.get());
      }
      else
      {
        buffer.append(INFO_FILE_CONSTRAINTS_DIR_MAY_EXIST.get());
      }
    }
    else
    {
      if (fileMustExist)
      {
        buffer.append(INFO_FILE_CONSTRAINTS_FILE_MUST_EXIST.get());
      }
      else if (parentMustExist)
      {
        buffer.append(INFO_FILE_CONSTRAINTS_FILE_PARENT_MUST_EXIST.get());
      }
      else
      {
        buffer.append(INFO_FILE_CONSTRAINTS_FILE_MAY_EXIST.get());
      }
    }

    if (relativeBaseDirectory != null)
    {
      buffer.append("  ");
      buffer.append(INFO_FILE_CONSTRAINTS_RELATIVE_PATH_SPECIFIED_ROOT.get(
           relativeBaseDirectory.getAbsolutePath()));
    }

    return buffer.toString();
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
  public FileArgument getCleanCopy()
  {
    return new FileArgument(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addToCommandLine(@NotNull final List<String> argStrings)
  {
    for (final File f : values)
    {
      argStrings.add(getIdentifierString());
      if (isSensitive())
      {
        argStrings.add("***REDACTED***");
      }
      else
      {
        argStrings.add(f.getAbsolutePath());
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("FileArgument(");
    appendBasicToStringInfo(buffer);

    buffer.append(", fileMustExist=");
    buffer.append(fileMustExist);
    buffer.append(", parentMustExist=");
    buffer.append(parentMustExist);
    buffer.append(", mustBeFile=");
    buffer.append(mustBeFile);
    buffer.append(", mustBeDirectory=");
    buffer.append(mustBeDirectory);

    if (relativeBaseDirectory != null)
    {
      buffer.append(", relativeBaseDirectory='");
      buffer.append(relativeBaseDirectory.getAbsolutePath());
      buffer.append('\'');
    }

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

        final Iterator<File> iterator = defaultValues.iterator();
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
