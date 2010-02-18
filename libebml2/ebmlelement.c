/*
 * $Id: ebmlelement.c 1323 2008-10-05 12:07:46Z robux4 $
 * Copyright (c) 2008, Matroska Foundation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Matroska Foundation nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY The Matroska Foundation ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL The Matroska Foundation BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "ebml/ebml.h"

static bool_t ValidateSize(ebml_element *p)
{
    return 1;
}

static void PostCreate(ebml_element *Element)
{
    Element->DefaultSize = -1;
    Element->ElementPosition = INVALID_FILEPOS_T;
    Element->SizePosition = INVALID_FILEPOS_T;
}

static err_t Create(ebml_element *Element)
{
    Element->Size = INVALID_FILEPOS_T;
    return ERR_NONE;
}

META_START(EBMLElement_Class,EBML_ELEMENT_CLASS)
META_CLASS(SIZE,sizeof(ebml_element))
META_CLASS(VMT_SIZE,sizeof(ebml_element_vmt))
META_CLASS(FLAGS,CFLAG_ABSTRACT)
META_CLASS(CREATE,Create)
META_VMT(TYPE_FUNC,ebml_element_vmt,PostCreate,PostCreate)
META_VMT(TYPE_FUNC,ebml_element_vmt,ValidateSize,ValidateSize)

META_PARAM(TYPE,EBML_ELEMENT_INFINITESIZE,TYPE_BOOLEAN)
META_DYNAMIC(EBML_ELEMENT_INFINITESIZE,TYPE_BOOLEAN)

META_PARAM(TYPE,EBML_ELEMENT_MASTERCONTEXT,TYPE_PTR)
META_DYNAMIC(EBML_ELEMENT_MASTERCONTEXT,TYPE_PTR)

META_END_CONTINUE(NODETREE_CLASS)

META_START_CONTINUE(EBML_DUMMY_ID)
META_CLASS(SIZE,sizeof(ebml_dummy))
META_END(EBML_BINARY_CLASS)

bool_t EBML_ElementIsFiniteSize(const ebml_element *Element)
{
    return (Node_GetData((const node*)Element,EBML_ELEMENT_INFINITESIZE,TYPE_BOOLEAN) == 0);
}

void EBML_ElementSetInfiniteSize(const ebml_element *Element)
{
    bool_t b = 1;
    Node_SetData((node*)Element,EBML_ELEMENT_INFINITESIZE,TYPE_BOOLEAN,&b);
}

bool_t EBML_ElementIsDummy(const ebml_element *Element)
{
    return Node_IsPartOf(Element,EBML_DUMMY_ID);
}

ebml_element *EBML_ElementSkipData(ebml_element *p, stream *Input, const ebml_parser_context *Context, ebml_element *TestReadElt, bool_t AllowDummyElt)
{
	ebml_element *Result = NULL;
	if (EBML_ElementIsFiniteSize(p)) {
		assert(TestReadElt == NULL);
		assert(p->ElementPosition < p->SizePosition);
		Stream_Seek(Input, p->SizePosition + EBML_CodedSizeLength(p->Size, p->SizeLength, 1) + p->Size, SEEK_SET);
	} else {
		// read elements until an upper element is found
		bool_t bEndFound = 0;
		while (!bEndFound && Result == NULL) {
			if (TestReadElt == NULL) {
				int bUpperElement = 0; // trick to call FindNextID correctly
				Result = EBML_FindNextElement(Input, Context, &bUpperElement, AllowDummyElt);
			} else {
				Result = TestReadElt;
			}
			
			if (Result != NULL) {
#ifdef TODO
				unsigned int EltIndex;
				// data known in this Master's context
				for (EltIndex = 0; EltIndex < Context.Size; EltIndex++) {
					if (EbmlId(*Result) == Context.MyTable[EltIndex].GetCallbacks.GlobalId) {
						// skip the data with its own context
						Result = Result->SkipData(DataStream, Context.MyTable[EltIndex].GetCallbacks.Context, NULL);
						break; // let's go to the next ID
					}
				}

				if (EltIndex >= Context.Size) {
					if (Context.UpTable != NULL) {
						Result = SkipData(DataStream, *Context.UpTable, Result);
					} else {
						assert(Context.GetGlobalContext != NULL);
						if (Context != Context.GetGlobalContext()) {
							Result = SkipData(DataStream, Context.GetGlobalContext(), Result);
						} else {
							bEndFound = 1;
						}
					}
				}
#endif
			} else {
				bEndFound = 1;
			}
		}
	}
	return Result;
}

static size_t GetIdLength(fourcc_t Id)
{
#if defined(IS_BIG_ENDIAN)
    if ((Id & 0x00FFFFFF)==0)
        return 1;
    if ((Id & 0x0000FFFF)==0)
        return 2;
    if ((Id & 0x000000FF)==0)
        return 3;
#else
    if ((Id & 0xFFFFFF00)==0)
        return 1;
    if ((Id & 0xFFFF0000)==0)
        return 2;
    if ((Id & 0xFF000000)==0)
        return 3;
#endif
    return 4;
}

filepos_t EBML_ElementFullSize(const ebml_element *Element, bool_t bKeepIntact)
{
	if (!bKeepIntact && EBML_ElementIsDefaultValue(Element))
		return INVALID_FILEPOS_T; // won't be saved
	return Element->Size + GetIdLength(Element->Context->Id) + EBML_CodedSizeLength(Element->Size, Element->SizeLength, EBML_ElementIsFiniteSize(Element));
}

#if defined(CONFIG_EBML_WRITING)
err_t EBML_ElementRender(ebml_element *Element, stream *Output, bool_t bKeepIntact, bool_t bKeepPosition, bool_t bForceRender, filepos_t *Rendered)
{
    err_t Result;
    filepos_t _Rendered,WrittenSize;
#if !defined(NDEBUG)
    filepos_t SupposedSize;
#endif

    if (!Rendered)
        Rendered = &_Rendered;
    *Rendered = 0;

    assert(Element->bValueIsSet || (bKeepIntact && Element->bDefaultIsSet)); // an element is been rendered without a value set !!!
		                 // it may be a mandatory element without a default value
	if (!bKeepIntact && EBML_ElementIsDefaultValue(Element))
		return ERR_INVALID_DATA;

#if !defined(NDEBUG)
	SupposedSize = EBML_ElementUpdateSize(Element,bKeepIntact, bForceRender);
#endif
	Result = EBML_ElementRenderHead(Element, Output, bForceRender, bKeepIntact, bKeepPosition, &WrittenSize);
    *Rendered += WrittenSize;
    if (Result != ERR_NONE)
        return Result;

    Result = EBML_ElementRenderData(Element, Output, bForceRender, bKeepIntact, &WrittenSize);
#if !defined(NDEBUG)
    if (SupposedSize != (0-1)) assert(WrittenSize == SupposedSize);
#endif
    *Rendered += WrittenSize;

    return Result;
}

static err_t MakeRenderHead(ebml_element *Element, stream *Output, bool_t bKeepPosition, filepos_t *Rendered)
{
    err_t Err;
	uint8_t FinalHead[4+8]; // Class D + 64 bits coded size
	size_t i,FinalHeadSize;
    int CodedSize;
    filepos_t PosAfter,PosBefore = Stream_Seek(Output,0,SEEK_CUR);
	
	FinalHeadSize = GetIdLength(Element->Context->Id);
#if defined(IS_BIG_ENDIAN)
    memcpy(FinalHead,&Element->Context->Id,FinalHeadSize);
#else
    for (i=0;i<FinalHeadSize;++i)
        FinalHead[i] = (uint8_t)(Element->Context->Id >> (i<<3));
#endif

	CodedSize = EBML_CodedSizeLength(Element->Size, Element->SizeLength, EBML_ElementIsFiniteSize(Element));
	EBML_CodedValueLength(Element->Size, CodedSize, &FinalHead[FinalHeadSize]);
	FinalHeadSize += CodedSize;
	
	Err = Stream_Write(Output, FinalHead, FinalHeadSize, &i);
    PosAfter = Stream_Seek(Output,0,SEEK_CUR);
	if (!bKeepPosition) {
		Element->ElementPosition = PosAfter - FinalHeadSize;
		Element->SizePosition = Element->ElementPosition + GetIdLength(Element->Context->Id);
	}
    if (Rendered)
        *Rendered = PosAfter - PosBefore;
	return Err;
}

err_t EBML_ElementRenderHead(ebml_element *Element, stream *Output, bool_t bForceRender, bool_t bKeepIntact, bool_t bKeepPosition, filepos_t *Rendered)
{
	EBML_ElementUpdateSize(Element,bKeepIntact, bForceRender); // TODO: use a flag to tell wether the Size needs to be updated or not
	
	return MakeRenderHead(Element, Output, bKeepPosition,Rendered);
}
#endif
