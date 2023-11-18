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
#include "rand.h"

// not going to bother fuzzing a small block
constexpr size_t MIN_BUFF_LEN = 16;

std::vector<std::string> naughtyStrings{};
bool naughtyStringsLoadAttempted = false;
RandomNumberGenerator rng;

// this is called multiple times, usually per block of data
bool Fuzz(_Inout_updates_bytes_(*pLen)	char* pBuf,
		  _Inout_						size_t* pLen,
		  _In_							unsigned int fuzzaggr) {

	// on first call, load the naughty strings file
	// the 'attempted' flag is to prevent trying to load the file
	// if the file does not exist or there's a load error
	if (naughtyStrings.empty() && !naughtyStringsLoadAttempted) {
		naughtyStringsLoadAttempted = true;

		std::ifstream inputFile("naughty.txt", std::ios::in | std::ios::binary);
		if (inputFile.is_open()) {
			std::string line;
			while (std::getline(inputFile, line)) {
				// Check if the line is non-empty and does not start with #
				if (!line.empty() && line.at(0) != '#') {
					naughtyStrings.push_back(line);
				}
			}
		}

		inputFile.close();
	}

	// don't fuzz everything
	if (rng.generatePercent() > fuzzaggr) {
		printf("Non");
		return false;
	}

	// check for nulls
	if (pBuf == nullptr || pLen == nullptr) {
		return false;
	}

	// if data is too small to fuzz, return false
	if (*pLen < MIN_BUFF_LEN) {
		return false;
	}

	// get a random range to fuzz
	size_t start{}, end{};
	do {
		start = rng.setRange(0, *pLen).generate();
		end = rng.setRange(0, *pLen).generate();
		if (start > end) {
			const size_t tmp = start;
			start = end;
			end = tmp;
		}
	} while (end - start < MIN_BUFF_LEN);

	// how many loops through the fuzzer?
	// most of the time, 10%, keep it at one iteration
	const unsigned int iterations = rng.setRange(0,10).generate() == 7
		? 1
		: 1 + rng.setRange(0, 10).generate();

	// This is where the work is done
	for (size_t i = 0; i < iterations; i++) {

		const unsigned int skip = rng.setRange(0, 10).generate() > 7 ? 1 + rng.setRange(0, 10).generate() : 1;
		const unsigned int whichMutation = rng.setRange(0, 10).generate();
		unsigned int j = 0;

		switch (whichMutation) {
		// set the range to a random byte
		case 0:
		{
			printf("Byt");
			const char byte = rng.generateChar();
			for (j = start; j < end; j += skip) {
				pBuf[j] = byte;
			}
		}
		break;

		// write random bytes to the range
		case 1:
		{
			printf("Rnd");
			for (j = start; j < end; j += skip) {
				pBuf[j] = rng.generateChar();
			}
		}
		break;

		// set upper bit
		case 2:
			printf("Sup");
			for (j = start; j < end; j += skip) {
				pBuf[j] |= 0x80;
			}
			break;

		// reset upper bit
		case 3:
			printf("Rup");
			for (j = start; j < end; j += skip) {
				pBuf[j] &= 0x7F;
			}
			break;

		// set the first zero-byte found to non-zero
		case 4:
		{
			printf("Zer");
			for (j = start; j < end; j += skip) {
				if (pBuf[j] == 0) {
					pBuf[j] = rng.generateChar();
					break;
				}
			}
		}
		break;

		// insert interesting edge-case numbers, often 2^n +/- 1
		case 5:
		{
			printf("Num");
			const int interestingNum[] = { 0,1,7,8,9,15,16,17,31,32,33,63,64,65,127,128,129,191,192,193,223,224,225,239,240,241,247,248,249,253,254,255 };
			for (j = start; j < end; j += skip) {
				pBuf[j] = gsl::narrow_cast<char>(interestingNum[rng.setRange(0, _countof(interestingNum)).generate()]);
			}
		}
		break;

		// interesting characters
		case 6:
		{
			printf("Chr");
			const char interestingChar[] = { '~', '!', ':', ';', '<', '>', '\\', '/', '.', '%', '-','#', '@', '?', '+', '=', '|', '\n', '\r', '\t', '*', '[', ']', '{', '}', '.'};
			for (j = start; j < end; j += skip) {
				pBuf[j] = interestingChar[rng.setRange(0, _countof(interestingChar)).generate()];
			}
		}
		break;

		// truncate
		case 7:
			printf("Trn");
			*pLen = end;
			break;

		// overlong UTF-8 encodings
		case 8: 
		{
			printf("Utf");
			std::vector<unsigned char> overlong;
			const int choice = rng.setRange(0,3).generate();
			const char base_char = rng.generateSmallInt();

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

				for (j = start; j < start + overlong.size(); j += skip) 
					pBuf[j] = overlong.at(j - start);
		}

		// insert naughty words
		case 9: 
			if (!naughtyStrings.empty()) {
				printf("Nau");

				const std::string& naughty = naughtyStrings.at(rng.setRange(0, naughtyStrings.size()).generate());
				for (j = start; j < start + naughty.size(); j++) {
					if (j < end) 
						pBuf[j] = naughty.at(j - start);
				}
			}
				break;

		default:
			break;
		}

	}

	return true;
}
