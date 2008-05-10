/*
 *    MSXML Class Factory
 *
 * Copyright 2005 Mike McCormack
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __MSXML_PRIVATE__
#define __MSXML_PRIVATE__

#ifndef __WINE_CONFIG_H
# error You must include config.h to use this header
#endif

#ifdef HAVE_LIBXML2

#ifdef HAVE_LIBXML_PARSER_H
#include <libxml/parser.h>
#endif

/* constructors */
extern IUnknown         *create_domdoc( void );
extern IUnknown         *create_xmldoc( void );
extern IXMLDOMNode      *create_node( xmlNodePtr node );
extern IUnknown         *create_basic_node( xmlNodePtr node, IUnknown *pUnkOuter );
extern IUnknown         *create_element( xmlNodePtr element, IUnknown *pUnkOuter );
extern IUnknown         *create_attribute( xmlNodePtr attribute );
extern IUnknown         *create_text( xmlNodePtr text );
extern IUnknown         *create_pi( xmlNodePtr pi );
extern IUnknown         *create_comment( xmlNodePtr comment );
extern IUnknown         *create_cdata( xmlNodePtr text );
extern IXMLDOMNodeList  *create_children_nodelist( xmlNodePtr );
extern IXMLDOMNamedNodeMap *create_nodemap( IXMLDOMNode *node );
extern IUnknown         *create_doc_Implementation();
extern IUnknown         *create_doc_fragment( xmlNodePtr fragment );
extern IUnknown         *create_doc_entity_ref( xmlNodePtr entity );

extern HRESULT queryresult_create( xmlNodePtr, LPWSTR, IXMLDOMNodeList ** );

extern void attach_xmlnode( IXMLDOMNode *node, xmlNodePtr xmlnode );

/* data accessors */
xmlNodePtr xmlNodePtr_from_domnode( IXMLDOMNode *iface, xmlElementType type );

/* helpers */
extern xmlChar *xmlChar_from_wchar( LPWSTR str );
extern BSTR bstr_from_xmlChar( const xmlChar *buf );

extern LONG xmldoc_add_ref( xmlDocPtr doc );
extern LONG xmldoc_release( xmlDocPtr doc );

extern HRESULT XMLElement_create( IUnknown *pUnkOuter, xmlNodePtr node, LPVOID *ppObj );
extern HRESULT XMLElementCollection_create( IUnknown *pUnkOuter, xmlNodePtr node, LPVOID *ppObj );

extern xmlDocPtr parse_xml(char *ptr, int len);

/* IXMLDOMNode Internal Structure */
typedef struct _xmlnode
{
    const struct IXMLDOMNodeVtbl *lpVtbl;
    const struct IUnknownVtbl *lpInternalUnkVtbl;
    IUnknown *pUnkOuter;
    LONG ref;
    xmlNodePtr node;
} xmlnode;

static inline xmlnode *impl_from_IXMLDOMNode( IXMLDOMNode *iface )
{
    return (xmlnode *)((char*)iface - FIELD_OFFSET(xmlnode, lpVtbl));
}

#endif

extern IXMLDOMParseError *create_parseError( LONG code, BSTR url, BSTR reason, BSTR srcText,
                                             LONG line, LONG linepos, LONG filepos );
extern HRESULT DOMDocument_create( IUnknown *pUnkOuter, LPVOID *ppObj );
extern HRESULT SchemaCache_create( IUnknown *pUnkOuter, LPVOID *ppObj );
extern HRESULT XMLDocument_create( IUnknown *pUnkOuter, LPVOID *ppObj );
extern HRESULT SAXXMLReader_create(IUnknown *pUnkOuter, LPVOID *ppObj );

/* typelibs */
enum tid_t {
    IXMLDOMAttribute_tid,
    IXMLDOMCDATASection_tid,
    IXMLDOMComment_tid,
    IXMLDOMDocument2_tid,
    IXMLDOMDocumentFragment_tid,
    IXMLDOMElement_tid,
    IXMLDOMEntityReference_tid,
    IXMLDOMImplementation_tid,
    IXMLDOMNamedNodeMap_tid,
    IXMLDOMNode_tid,
    IXMLDOMNodeList_tid,
    IXMLDOMParseError_tid,
    IXMLDOMProcessingInstruction_tid,
    IXMLDOMSchemaCollection_tid,
    IXMLDOMText_tid,
    IXMLElement_tid,
    IXMLDocument_tid,
    IVBSAXAttributes_tid,
    IVBSAXContentHandler_tid,
    IVBSAXDeclHandler_tid,
    IVBSAXDTDHandler_tid,
    IVBSAXEntityResolver_tid,
    IVBSAXErrorHandler_tid,
    IVBSAXLexicalHandler_tid,
    IVBSAXLocator_tid,
    IVBSAXXMLFilter_tid,
    IVBSAXXMLReader_tid,
    IMXAttributes_tid,
    IMXReaderControl_tid,
    IMXWriter_tid,
    LAST_tid
};

extern HRESULT get_typeinfo(enum tid_t tid, ITypeInfo **typeinfo);
extern ITypeLib *get_msxml3_typelib( LPWSTR *path );

#endif /* __MSXML_PRIVATE__ */
