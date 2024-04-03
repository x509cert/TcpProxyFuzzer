#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <sal.h>
#include <memory>
#include <cstdio>
#include <vector>
#include <iostream>
#include <fstream>
#include <string>
#include <locale>
#include <codecvt>
#include <vector>
#include <algorithm>
#include <iterator>  

#include "Logger.h"
#include "rand.h"
#include "gsl\narrow"

// Using Microsoft C++ Guidelines Support Library (GSL) 
// https://github.com/microsoft/GSL/tree/main 
// GSL's span() comes with bounds checking
// Read this for background on why this code use gsl::span() and not std::span()
// https://github.com/microsoft/GSL/blob/main/docs/headers.md#gslspan
#include "gsl\span" 

// all the possible fuzz mutation types
enum class FuzzMutation : uint32_t {
	None,
	RndByteSingle,
	RndByteMultiple,
	ChangeASCIIInt, 
	SetUpperBit,
	ResetUpperBit,
	ZeroByteToNonZero,
	InterestingNumber,
	InterestingChar,
	Truncate,
	Grow,
	OverlongUtf8,
	NaughtyWord,
	RndUnicode,
	ReplaceInterestingChar,
	Max
};

#pragma region Globals

#ifdef _DEBUG
extern Logger gLog;
#endif

// not going to bother fuzzing a small block
constexpr size_t MIN_BUFF_LEN = 16;

const std::string interestingChar{ "~!:;\\/,.%-_`$^&#@?+=|\n\r\t\a*<>()[]{}\'\b\v\"\f" };

std::vector<std::string> naughty{};
bool naughtyLoadAttempted = false;

std::vector<std::string> naughtyJson{};
bool naughtyJsonLoadAttempted = false;

std::vector<std::string> naughtyHtml{};
bool naughtyHtmlLoadAttempted = false;

std::vector<std::string> naughtyXml{};
bool naughtyXmlLoadAttempted = false;

RandomNumberGenerator rng{};
#pragma endregion Globals

#pragma region RNG and Naughty Files

#pragma warning(push)
#pragma warning(disable: 4996) // UTF8 encoding is deprecated, need to fix

// Generates a random Unicode character
std::string GetRandomUnicodeCharacter() {

	auto codePoint = rng.range(0x0000,0xFFFF).generate();

	// Avoid surrogate pair range, but recursively generate again if in surrogate pair range
	if (codePoint >= 0xD800 && codePoint <= 0xDFFF) 
		return GetRandomUnicodeCharacter(); 

	std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
	return converter.to_bytes(std::wstring(1, gsl::narrow<wchar_t>(codePoint)));
}
#pragma warning(pop)

// Load a file of naughty strings
static void LoadNaughtyFile(std::string filename, std::vector<std::string>& words) {
#ifdef _DEBUG
	gLog.Log(1, false, std::format("Loading %s", filename));
#endif
	std::ifstream inputFile(filename, std::ios::in | std::ios::binary);
	if (inputFile.is_open()) {
		std::string line;
		while (std::getline(inputFile, line)) {
			// Check if the line is non-empty and does not start with # (a comment)
			if (!line.empty() && line.at(0) != '#') {
				words.push_back(line);
			}
		}
	} else {
#ifdef _DEBUG
		gLog.Log(1, false, std::format("Error loading %s, err=%d", filename, errno));
#endif
	}
}

// gets a naughty string from the appropriate file depending on fuzz_type
std::string GetNaughtyString(unsigned int fuzz_type) {
	std::string ret{ };
	switch (fuzz_type) {
		case 'j': {
				const auto len = gsl::narrow_cast<unsigned int>(naughtyJson.size());
				if (len) {
					ret = naughtyJson.at(rng.range(0, len).generate());
				}
			}
			break;

		case 't': {
				const auto len = gsl::narrow_cast<unsigned int>(naughty.size());
				if (len) {
					ret = naughty.at(rng.range(0, len).generate());
				}
			}
			break;

		case 'x': {
				const auto len = gsl::narrow_cast<unsigned int>(naughtyXml.size());
				if (len) {
					ret = naughtyXml.at(rng.range(0, len).generate());
				}
			}
			break;

		case 'h': {
				const auto len = gsl::narrow_cast<unsigned int>(naughtyHtml.size());
				if (len) {
					ret = naughtyHtml.at(rng.range(0, len).generate());
				}
			}
			break;

		default:
			break;
	}

	return ret;
}

#pragma endregion RNG and Naughty Files

#pragma region Fuzzing

// This is called multiple times, usually per block of data
bool Fuzz(std::vector<char>& buffer, unsigned int fuzzaggr, unsigned int fuzz_type, unsigned int offset) {

	// don't fuzz everything
	// check data is not too small to fuzz
	// arbitrary decision, the offset can be no more than 50% of the buffer size
	auto bufflen = buffer.size();
	if (bufflen < MIN_BUFF_LEN || rng.generatePercent() > fuzzaggr || offset >= bufflen/2) {
		fprintf(stderr, "Nnn");
#ifdef _DEBUG
		gLog.Log(1, false, "Nnn");
#endif
		return false;
	}

	// On first call, load the naughty strings file, but only if fuzz_type is not 'b'
	// the 'attempted' flag is to prevent trying to load the file
	// if the file does not exist or there's a load error
	if (fuzz_type == 't' && naughty.empty() && !naughtyLoadAttempted) {
		naughtyLoadAttempted = true;
		LoadNaughtyFile("naughty.txt", naughty);
	}

	// XML Naughty Strings
	if (fuzz_type == 'x' && naughtyXml.empty() && !naughtyXmlLoadAttempted) {
		naughtyXmlLoadAttempted = true;
		LoadNaughtyFile("naughty_Xml.txt", naughtyXml);
	}

	// HTML Naughty Strings
	if (fuzz_type == 'h' && naughtyHtml.empty() && !naughtyHtmlLoadAttempted) {
		naughtyHtmlLoadAttempted = true;
		LoadNaughtyFile("naughty_Html.txt", naughtyHtml);
	}

	// JSON Naughty Strings
	if (fuzz_type == 'j' && naughtyJson.empty() && !naughtyJsonLoadAttempted) {
		naughtyJsonLoadAttempted = true;
		LoadNaughtyFile("naughty_Json.txt", naughtyJson);
	}

	// get a random range to fuzz, make sure it's big enough, but not too big!
	size_t start{}, start_offset{}, end{ };
	do {
		auto intermediate = bufflen - gsl::narrow_cast<size_t>(offset);
		start = rng.range(offset, gsl::narrow_cast<unsigned int>(intermediate)).generate();
		start_offset = rng.range(0, gsl::narrow_cast<unsigned int>(bufflen)).generate();
		start_offset /= 8;
		start_offset++;
	} while (start + start_offset < bufflen); //TODO - double check this won't loop forever!

	end = start + start_offset;

	// if we need to leave the main fuzzing loop quickly
	bool earlyExit = false;

	// How many loops through the fuzzer?
	// Use a poisson distribution around median == 2.5
	// Gives a distribution like this:
	//  0 : ******************************
	//	1 : **********************************************************************
	//	2 : *************************************************************************************
	//	3 : ********************************************************************
	//	4 : *****************************************
	//	5 : *********************
	//	6 : *********
	//	7 : ***
	//	8 : *

	constexpr auto mean = 2.5;
	const auto iterations = gsl::narrow_cast<unsigned int>(rng.generatePoission(mean));

#ifdef _DEBUG
	gLog.Log(0, false, std::format("Iter:{0}, Start:{1}, End:{2}", iterations, start, end));
#endif

	// This is where the work is done
	for (size_t i = 0; i < iterations; i++) {

		// when laying down random chars, skip every N-bytes
		// 70% of the time, skip 1-byte at a time
		const size_t skip = rng.range(0, 10).generate() < 7
			? 1
			: rng.range(1, 10).generate();
		
		// which mutation to use. 
		// The upper-range is updated automatically as new mutations are added
		const auto whichMutation 
			= static_cast<FuzzMutation>(rng.range(0, static_cast<unsigned int>(FuzzMutation::Max)).generate());

		switch (whichMutation) {
			///////////////////////////////////////////////////////////
			// no mutation
			case FuzzMutation::None:
				fprintf(stderr,"Non");
#ifdef _DEBUG
				gLog.Log(1, false, "Non");
#endif
				break;

			///////////////////////////////////////////////////////////
			// set the range to a random byte
			case FuzzMutation::RndByteSingle:
			{
				fprintf(stderr, "Byt");
#ifdef _DEBUG
				gLog.Log(1, false, "Byt");
#endif
				const char byte = rng.generateChar();
				for (size_t j = start; j < end; j += skip) {
					buffer.at(j) = byte;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// write random bytes to the range
			case FuzzMutation::RndByteMultiple:
			{
				fprintf(stderr, "Rnd");
#ifdef _DEBUG
				gLog.Log(1, false, "Rnd");
#endif
				for (size_t j = start; j < end; j += skip) {
					buffer.at(j) = rng.generateChar();
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// a variant of above
			case FuzzMutation::ChangeASCIIInt:
			{
				fprintf(stderr,"Chg");
#ifdef _DEBUG
				gLog.Log(1, false, "Chg");
#endif
				for (size_t j = start; j < end; j += skip) {
					auto c = buffer.at(j);
					switch (rng.range(0, 4).generate()) {
						case 0	: c++;	break;
						case 1	: c--;	break;
						case 2	: c/=2; break;
						default	: c*=2; break;
					}

					buffer.at(j) = c;
				}
			}
			break;
			
			///////////////////////////////////////////////////////////
			// set upper bit
			case FuzzMutation::SetUpperBit:
			{
				fprintf(stderr,"Sup");
#ifdef _DEBUG
				gLog.Log(1, false, "Sup");
#endif
				for (size_t j = start; j < end; j += skip) {
					buffer.at(j) |= 0x80;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// reset upper bit
			case FuzzMutation::ResetUpperBit:
			{
				fprintf(stderr,"Rup");
#ifdef _DEBUG
				gLog.Log(1, false, "Rup");
#endif
				for (size_t j = start; j < end; j += skip) {
					buffer.at(j) &= 0x7F;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// set the first zero-byte found to non-zero
			case FuzzMutation::ZeroByteToNonZero:
			{
				fprintf(stderr,"Zer");
#ifdef _DEBUG
				gLog.Log(1, false, "Zer");
#endif
				for (size_t j = start; j < end; j++) {
					if (buffer.at(j) == 0) {
						buffer.at(j) = rng.generateChar();
						break;
					}
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// insert interesting edge-case numbers, often 2^n +/- 1
			case FuzzMutation::InterestingNumber:
			{
				fprintf(stderr,"Num");
#ifdef _DEBUG
				gLog.Log(1, false, "Num");
#endif
				const int interestingNum[] 
					= { 0,1,2,3,4,5,7,8,9,15,16,17,31,32,
						33,63,64,65,127,128,129,191,192,193,
						223,224,225,239,240,241,247,248,249,253,
						254,255 };
				
				for (size_t j = start; j < end; j += skip) {
					const auto which = rng.range(0, _countof(interestingNum)).generate();
					auto ch = gsl::narrow<unsigned char>(gsl::at(interestingNum, which));
					buffer.at(j) = ch;
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// insert interesting characters
			case FuzzMutation::InterestingChar:
			{
				fprintf(stderr,"Chr");
#ifdef _DEBUG
				gLog.Log(1, false, "Chr");
#endif
				for (size_t j = start; j < end; j += skip) {
					const auto which = rng.range(0, gsl::narrow<unsigned int>(interestingChar.length())).generate();
					buffer.at(j) = gsl::at(interestingChar,which);
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// replace interesting characters with space
			case FuzzMutation::ReplaceInterestingChar:
			{
				fprintf(stderr,"Rep");
#ifdef _DEBUG
				gLog.Log(1, false, "Rep");
#endif
				for (size_t j = start; j < end; j++) {
					auto ch = buffer.at(j);
					if (interestingChar.find(ch) != std::string::npos) {
						buffer.at(j) = rng.generateChar();

						// 50% chance to break out of the loop and not tweak all characters
						if(rng.range(0, 10).generate() >= 5)
							break;
					}
				}
			}
			break;

			///////////////////////////////////////////////////////////
			// truncate the buffer
			case FuzzMutation::Truncate:
			{
				fprintf(stderr,"Trn");

				bufflen = gsl::narrow<unsigned int>(end);
				buffer.resize(bufflen);
				earlyExit = true;
#ifdef _DEBUG
				gLog.Log(1, false, std::format("Trn->size: {0}", bufflen));
#endif

			}
			break;

			///////////////////////////////////////////////////////////
			// grow the buffer
			case FuzzMutation::Grow:
			{
				fprintf(stderr,"Gro");

				// take the midpoint of the start and end, 
				// and determine how much to grow the buffer
				const size_t insert_point = (end - start) / 2;
				const size_t fillsize = rng.range(4, 128).generate();

#ifdef _DEBUG
				gLog.Log(1, false, std::format("Gro->mid: At {0}, size: {1}", insert_point, fillsize));
#endif
				// this vector will contain the insertion string, 
				// it is set to all nulls to start
				std::vector<char> insert(fillsize);

				switch (fuzz_type) {
						
					case 'j': //TODO - need to complete this
					{
						//TODO Replace with fn()
						const auto len = gsl::narrow_cast<unsigned int>(naughtyJson.size());
						if (len) {
							std::string data = naughtyJson.at(rng.range(0, len).generate());
							auto replace_size = std::min(data.length(), fillsize);
							std::copy(data.begin(), data.begin() + replace_size, insert.begin());
#ifdef _DEBUG
							gLog.Log(2, false, std::format("Repl Size (J): {0}", replace_size));
#endif
						}
					}
					break;

					case 'x': //TODO - need to complete this
					{
						const auto len = gsl::narrow_cast<unsigned int>(naughtyXml.size());
						if (len) {
							std::string data = naughtyXml.at(rng.range(0, len).generate());
							auto replace_size = std::min(data.length(), fillsize);
							std::copy(data.begin(), data.begin() + replace_size, insert.begin());
#ifdef _DEBUG
							gLog.Log(2, false, std::format("Repl Size (X): {0}", replace_size));
#endif
						}
					}
					break;

					case 'h': //TODO - need to complete this
					{
						const auto len = gsl::narrow_cast<unsigned int>(naughtyHtml.size());
						if (len) {
							std::string data = naughtyHtml.at(rng.range(0, len).generate());
							auto replace_size = std::min(data.length(), fillsize);
							std::copy(data.begin(), data.begin() + replace_size, insert.begin());							
#ifdef _DEBUG
							gLog.Log(2, false, std::format("Repl Size (H): {0}", replace_size));
#endif
						}
					}
					break;

					case 'b':
					default:
					{
						// 50% chance to fill with random characters
						// 50% chance to fill with the same random character
						if (rng.range(0,10).generate() % 2) {
							for (char& c : insert)
								c = rng.generateChar();
						} else {
							auto r = rng.generateChar();
							for (char& c : insert)
								c = r;
						}

						break;
					}
				}

				buffer.insert(buffer.begin() + insert_point, insert.begin(), insert.end());
				earlyExit = true;
			}
			break;

			///////////////////////////////////////////////////////////
			// overlong UTF-8 encodings
			case FuzzMutation::OverlongUtf8: 
			{
				fprintf(stderr,"Utf");
#ifdef _DEBUG
				gLog.Log(1, false, "Utf");
#endif
				std::vector<unsigned char> overlong;
				const unsigned int choice = rng.range(0,3).generate();
				const char base_char = rng.generateChar();

				// just to make sure we don't run off the end of the buffer
				// max encoding len in 4, so this is a little more conservative
				// TODO: might use int overflow checks here instead
				if (end-start < MIN_BUFF_LEN/2)
					start = end - MIN_BUFF_LEN/2;

				switch (choice) {

					case 0:
						// 2-byte overlong encoding
						overlong.push_back(0b11000000 | (base_char >> 6));
						overlong.push_back(0b10000000 | (base_char & 0b00111111));
						break;

					case 1:
						// 3-byte overlong encoding
						overlong.push_back(0b11100000);
						overlong.push_back(0b10000000 | (base_char >> 6));
						overlong.push_back(0b10000000 | (base_char & 0b00111111));
						break;

					case 2:
						// 4-byte overlong encoding
						overlong.push_back(0b11110000);
						overlong.push_back(0b10000000 | (base_char >> 6));
						overlong.push_back(0b10000000 | (base_char & 0b00111111));
						overlong.push_back(0b10000000);
						break;

					default:
						break;
				}

				for (size_t j = start; j < start + overlong.size(); j++)
					buffer.at(j) = overlong.at(j - start);
			}

			break;

			///////////////////////////////////////////////////////////
			// insert naughty words
			// but not if we're doing binary fuzzing
			case FuzzMutation::NaughtyWord:
			{
				if (fuzz_type != 'b') {
					fprintf(stderr,"Nau");
#ifdef _DEBUG
					gLog.Log(1, false, "Nau");
#endif
					std::string nty = GetNaughtyString(fuzz_type);

					for (size_t j = start; j < start + nty.size() && j < end; j++) {
						buffer.at(j) = nty.at(j - start);
					}
				}
			}

			break;

			///////////////////////////////////////////////////////////
			// insert random Unicode (encoded as UTF-8)
			case FuzzMutation::RndUnicode: 
			{
				fprintf(stderr,"Uni");
#ifdef _DEBUG
				gLog.Log(1, false, "Uni");
#endif
				auto utf8char = GetRandomUnicodeCharacter();
				for (unsigned char byte : utf8char) {
					for (size_t j = start; j < start + utf8char.length() && j < end; j++)
						buffer.at(j) = byte;
				}
			}

			break;

			default:
				fprintf(stderr,"???");
#ifdef _DEBUG
				gLog.Log(1, false, "???");
#endif
				break;
		}

		// right now, this only happens on buffer size change because we need 
		// to re-calc buffer sizes and this is the safest way to do it
		if (earlyExit == true)
			break; 
	}

	return true;
}

#pragma endregion Fuzzing