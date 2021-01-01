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
package com.unboundid.ldap.sdk.schema;



import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This enum defines the types of elements that can make up an LDAP schema.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum SchemaElementType
{
  /**
   * The schema element type used to indicate the type of data that an attribute
   * of a given type can hold.
   */
  ATTRIBUTE_SYNTAX("attribute-syntax", Schema.ATTR_ATTRIBUTE_SYNTAX),



  /**
   * The schema element type used to indicate how to perform matching operations
   * against values for attributes of a given type.
   */
  MATCHING_RULE("matching-rule", Schema.ATTR_MATCHING_RULE),



  /**
   * The schema element type used to hold provide information about an
   * attribute.
   */
  ATTRIBUTE_TYPE("attribute-type", Schema.ATTR_ATTRIBUTE_TYPE),



  /**
   * The schema element type used to define the sets of attributes that may be
   * present in different types of entries.
   */
  OBJECT_CLASS("object-class", Schema.ATTR_OBJECT_CLASS),



  /**
   * The schema element type used to define the types of attributes that must
   * and may be present in the RDN of an entry with a given structural object
   * class.
   */
  NAME_FORM("name-form", Schema.ATTR_NAME_FORM),



  /**
   * The schema element type used to define additional constraints about
   * attributes with a given structural object class, including allowed
   * auxiliary object classes and required, optional, and prohibited attribute
   * types.
   */
  DIT_CONTENT_RULE("dit-content-rule", Schema.ATTR_DIT_CONTENT_RULE),



  /**
   * The schema element type used to define allowed hierarchical relationships
   * between entries with different types of structural object classes.
   */
  DIT_STRUCTURE_RULE("dit-structure-rule", Schema.ATTR_DIT_STRUCTURE_RULE),



  /**
   * The schema element type that may be used to restrict the set of attribute
   * types with which a matching rule may be used.
   */
  MATCHING_RULE_USE("matching-rule-use", Schema.ATTR_MATCHING_RULE_USE);



  // A name for this schema element type.
  @NotNull private final String name;

  // The name used to hold definitions for elements of this type in a subschema
  // subentry.
  @NotNull private final String subschemaAttributeTypeName;



  /**
   * Creates a new schema element type with the provided information.
   *
   * @param  name                        A name for this schema element type.
   * @param  subschemaAttributeTypeName  The name used to hold definitions for
   *                                     elements of this type in a subschema
   *                                     subentry.
   */
  SchemaElementType(@NotNull final String name,
                    @NotNull final String subschemaAttributeTypeName)
  {
    this.name = name;
    this.subschemaAttributeTypeName = subschemaAttributeTypeName;
  }



  /**
   * Retrieves the name for this schema element type.
   *
   * @return  The name for this schema element type.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the name used to hold definitions for elements of this type in a
   * subschema subentry.
   *
   * @return  The name used to hold definitions for elements of this type in a
   *          subschema subentry.
   */
  @NotNull()
  public String getSubschemaAttributeTypeName()
  {
    return subschemaAttributeTypeName;
  }



  /**
   * Retrieves the schema element type with the given name.
   *
   * @param  name  The name for the schema element type to retrieve.  It must
   *               not be {@code null}.
   *
   * @return  The schema element type with the given name, or {@code null} if
   *          there is no schema element type with that name.
   */
  @Nullable()
  public static SchemaElementType forName(@NotNull final String name)
  {
    final String lowerName = StaticUtils.toLowerCase(name.replace('_', '-'));
    switch (lowerName)
    {
      case "as":
      case "syntax":
      case "syntaxes":
      case "attributesyntax":
      case "attribute-syntax":
      case "attributesyntaxes":
      case "attribute-syntaxes":
      case "attributetypesyntax":
      case "attribute-type-syntax":
      case "attributetypesyntaxes":
      case "attribute-type-syntaxes":
      case "attrsyntax":
      case "attr-syntax":
      case "attrsyntaxes":
      case "attr-syntaxes":
      case "attrtypesyntax":
      case "attr-type-syntax":
      case "attrtypesyntaxes":
      case "attr-type-syntaxes":
      case "ldapsyntax":
      case "ldap-syntax":
      case "ldapsyntaxes":
      case "ldap-syntaxes":
        return ATTRIBUTE_SYNTAX;

      case "mr":
      case "matchingrule":
      case "matching-rule":
      case "matchingrules":
      case "matching-rules":
        return MATCHING_RULE;

      case "at":
      case "type":
      case "types":
      case "attributetype":
      case "attribute-type":
      case "attributetypes":
      case "attribute-types":
      case "attrtype":
      case "attr-type":
      case "attrtypes":
      case "attr-types":
        return ATTRIBUTE_TYPE;

      case "oc":
      case "class":
      case "classes":
      case "objectclass":
      case "object-class":
      case "objectclasses":
      case "object-classes":
        return OBJECT_CLASS;

      case "nf":
      case "form":
      case "forms":
      case "nameform":
      case "name-form":
      case "nameforms":
      case "name-forms":
        return NAME_FORM;

      case "dcr":
      case "contentrule":
      case "content-rule":
      case "contentrules":
      case "content-rules":
      case "ditcontentrule":
      case "dit-content-rule":
      case "ditcontentrules":
      case "dit-content-rules":
        return DIT_CONTENT_RULE;

      case "dsr":
      case "structurerule":
      case "structure-rule":
      case "structurerules":
      case "structure-rules":
      case "ditstructurerule":
      case "dit-structure-rule":
      case "ditstructurerules":
      case "dit-structure-rules":
        return DIT_STRUCTURE_RULE;

      case "mru":
      case "use":
      case "uses":
      case "matchingruleuse":
      case "matching-rule-use":
      case "matchingruleuses":
      case "matching-rule-uses":
        return MATCHING_RULE_USE;

      default:
        return null;
    }
  }



  /**
   * Retrieves a string representation of this schema element type.
   *
   * @return  A string representation of this schema element type.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return name;
  }
}
