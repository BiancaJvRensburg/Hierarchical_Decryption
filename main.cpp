// RijndaelAES.cpp : Defines the entry point for the console application.
//
// Rotate bit to left or right.

//Revision 2016-------------------------------------------------
#include "librairie.h"
#include "image_ppm.h"
#include <iostream>
#include <vector>
#include <bitset>
#include <Eigen/Dense>
#include <igl/readOFF.h>
#include <igl/writeOFF.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <igl/hausdorff.h>

#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

#define MANT_SIZE 23

using namespace std;

// Fonctions Jos�
uint* uintXOR(uint z[4], uint s[4]) {
	// Cette fonction: Faire un XOR dans un vecteur uint
		//uint *R = new uint[4];
	uint* R;
	allocation_tableau(R, uint, 4);
	R[0] = z[0] ^ s[0]; R[1] = z[1] ^ s[1]; R[2] = z[2] ^ s[2]; R[3] = z[3] ^ s[3];
	return R;
}

OCTET BlockEqual(OCTET WB1[16], OCTET WB2[16]) {
	// Cette fonction: Vérifie si les deux bloques sont pareils.
	OCTET i;
	for (i = 0; i < 16; i++)
		if (WB1[i] != WB2[i]) return 0;

	return 1;
}

void SubKey(uint WBinIn[4]) {
	// Cette fonction: Prendre la ligne et colonne dans le tableau S-BOX pour chaque octet dans le uint
	OCTET i;
	for (i = 0; i < 4; i++)
		WBinIn[i] = GetS_BOX(WBinIn[i]);
}

OCTET* _4UintColTo16Pixel(const uint WBinIn[]) {
	// Cette fonction: Entre 4 uint et sort une bloque de 16 octet hexad�imal.
		//OCTET *pixAES = new OCTET[16];
	OCTET* pixAES;
	allocation_tableau(pixAES, OCTET, 16);
	int nAux = 0;
	OCTET i;
	OCTET j;
	for (i = 0; i < 4; i++)
		for (j = 0; j < 4; j++)
			pixAES[nAux++] = GETOCTET(WBinIn[j], i);

	return pixAES;
}

void _16PixelTo4UintHex(const OCTET pix[16], uint WordBin[4]) {
	// Cette fonction: Entre une bloque de 16 octet hexadécimal et sort 4 uint par colonne.
	OCTET i;
	OCTET j;
	for (i = 0; i < 4; i++)
		for (j = 0; j < 4; j++)
			WordBin[i] = (WordBin[i] << 8) | pix[4 * j + i];
}

void AddRound(uint WBinIn[4], const uint RoundKey[4]) {
	// Cette fonction: Faire un XOR avec la cl�d��trait�
	OCTET i;
	for (i = 0; i < 4; i++)
		WBinIn[i] ^= RoundKey[i];
}

void ShowBlock(char* c, const uint WB[4]) {
	// Cette fonction: Montre les bloques pour une verification visuel.
	OCTET i;
	printf("\n%s\n", c);
	for (i = 0; i < 4; i++)
		printf(" %02x %02x %02x %02x \n", GETOCTET(WB[0], i), GETOCTET(WB[1], i), GETOCTET(WB[2], i), GETOCTET(WB[3], i));
}

void InvSubKey(uint WBinIn[4]) {
	// Cette fonction: C�t l'inverse du SubKey.
	OCTET i;
	for (i = 0; i < 4; i++)
		WBinIn[i] = InvGetS_BOX(WBinIn[i]);
}

void AES(int taille_image, OCTET* image_lue, OCTET* image_ecrite, char cryptage) {
	int aaa, temp, nRest;

	OCTET* BlockAESR = nullptr, * BlockAESV = nullptr, * BlockAESB = nullptr;
	OCTET nCntBlock = 0, BlockInR[16] = { 0 }, BlockInV[16] = { 0 }, BlockInB[16] = { 0 };

	BlockInR[0] = image_lue[0];
	temp = 0;
	uint nCntImgOut = 0;

	for (int i = 1; i <= taille_image; i++)
	{

		if (i % TAILLEBLOCKBYTE)	// Fill a block to be encrypted/decrypted (16 bytes per block = 128 bits)
		{
			temp = i % TAILLEBLOCKBYTE;
			BlockInR[temp] = image_lue[i];
			continue;
		}

		nCntBlock = 0;
		nCntImgOut = i - TAILLEBLOCKBYTE;

		if (cryptage == 'C')		// Encrypt or decrypt
		{
			BlockAESR = EncrypterAESMode(BlockInR);
		}
		else
		{
			BlockAESR = DecrypterAESMode(BlockInR);
		}

		if ((i + 20) > taille_image) aaa = 0;

		while (nCntBlock < TAILLEBLOCKBYTE)
		{
			image_ecrite[nCntImgOut] = BlockAESR[nCntBlock];
			nCntImgOut++;
			nCntBlock++;
		}

		BlockInR[i % TAILLEBLOCKBYTE] = image_lue[i];
	}

	/****** Si la taille d'image n'est pas multiple de 16. Faire le reste d'image.*********/
	nRest = (int)(taille_image / TAILLEBLOCKBYTE * TAILLEBLOCKBYTE);

	if (taille_image % TAILLEBLOCKBYTE)
	{
		for (int j = nRest; j < taille_image; j++)
		{
			image_ecrite[j] = image_lue[j];
		}
	}
	/*************************************************************************************/
	
	free(BlockAESR);
}

/*************************************************************************************/

// Global variable
uint RoundKey[15][4] = { 0 }, uintIV[4] = { 0 };
char Type_mode;
uint* pWordBinAnt = NULL;


void KeySchedule(const OCTET KeyOrig[64], uint RoundKey[15][4])
{
	OCTET i;
	uint nAux = 0;

	// RoudKey[0] and RoundKey[1] are the original key.
	OCTET keyP1[32];
	OCTET keyP2[32];
	for (int i = 0; i < 32; i++) {
		keyP1[i] = KeyOrig[i];
		keyP2[i] = KeyOrig[i + 32];
	}
	_32HexTo4UintCol(keyP1, RoundKey[0]);
	_32HexTo4UintCol(keyP2, RoundKey[1]);

	for (i = 2; i <= 14; i++) {

		// Treat the special case (mod 8 == 0)
		if (i % 2 == 0) {
			nAux = HOTWORD(RoundKey[i - 1][3]);
			nAux = GetS_BOX(nAux);
			RoundKey[i][0] = RoundKey[i - 1][0] ^ nAux ^ rcon[i - 1];
		}
		else {
			nAux = GetS_BOX(RoundKey[i - 1][3]);
			RoundKey[i][0] = RoundKey[i - 1][0] ^ nAux;
		}
		
		// Regualar xor for the rest
		for (int j = 1; j <= 3; j++) {
			RoundKey[i][j] = RoundKey[i][j-1] ^ RoundKey[i - 2][j];
		}
	}
}

// Deal with the encryption mode: one round of AES encryption
OCTET* EncrypterAESMode(const OCTET c[16])
{
	uint WordBin[4] = { 0 };
	//uint *pUint = new uint[4];
	uint* pUint;
	allocation_tableau(pUint, uint, 4);
	_16PixelTo4UintHex(c, WordBin);		//	ShowBlock("Original Block", WordBin);

	switch (Type_mode) {
	case '0':	// Mode ECB default du AES.

		EncrypterAES(WordBin);
		return _4UintColTo16Pixel(WordBin);

	case '1':	// Mode CBC. (Yo = IV), Yi = EK(Yi-1 XOR Xi), i >= 1.

		pWordBinAnt = EncrypterAES(uintXOR(pWordBinAnt, WordBin));
		return _4UintColTo16Pixel(pWordBinAnt);

	case '2': // Mode OFB.  (Zo = IV), Zi = EK(Zi-1), i >= 1. (Yi = Zi XOR Xi), i >= 1
		pWordBinAnt = EncrypterAES(pWordBinAnt);
		pUint = uintXOR(pWordBinAnt, WordBin);
		return _4UintColTo16Pixel(pUint);
		break;

	case '3': // Mode CFB. (Yo=IV), Zi = EK(Yi-1), i >= 1, Yi= Zi XOR Xi, i >= 1.
		pWordBinAnt = EncrypterAES(pWordBinAnt);
		pWordBinAnt = uintXOR(pWordBinAnt, WordBin);
		return _4UintColTo16Pixel(pWordBinAnt);
		break;
	}

	return _4UintColTo16Pixel(WordBin);
}

//------------------------------------------------------------
// Fonctions de Jos�Marconi M. Rodrigues
//------------------------------------------------------------

// A single round of AES
uint* EncrypterAES(uint WordBin[4])
{
	int i;
	// Cette fonction: Faire toutes les etapes de cryptage.
	AddRound(WordBin, RoundKey[0]);		//	ShowBlock("AddRound", WordBin);

// Rounds
	for (i = 1; i < 10; i++) {

		SubKey(WordBin);				//	ShowBlock("SubKey",   WordBin);

		ShiftRow(WordBin);				//	ShowBlock("ShiftRow", WordBin);

		MixColumn(WordBin);				//	ShowBlock("MixColumn",WordBin);

		AddRound(WordBin, RoundKey[i]);	//	ShowBlock("AddRound", WordBin);
	}

	SubKey(WordBin);					//	ShowBlock("SubKey",   WordBin);

	ShiftRow(WordBin);					//	ShowBlock("ShiftRow", WordBin);

	AddRound(WordBin, RoundKey[10]);	//	ShowBlock("AddRound", WordBin);

	return WordBin;
}

OCTET* DecrypterAESMode(const OCTET c[16])
{
	uint WordBin[4] = { 0 };
	//uint *pOrig = new uint[4];
	uint* pOrig;
	allocation_tableau(pOrig, uint, 4);
	_16PixelTo4UintHex(c, WordBin);		//	ShowBlock("Original Block", WordBin);

	switch (Type_mode) {
	case '0':	// Mode ECB default du AES.
		return _4UintColTo16Pixel(DecrypterAES(WordBin));

	case '1':	// Mode CBC. (Yo = IV), Yi = EK(Yi-1 XOR Xi), i >= 1.

		pOrig = uintXOR(pWordBinAnt, DecrypterAES(WordBin));

		pWordBinAnt[0] = WordBin[0];
		pWordBinAnt[1] = WordBin[1];
		pWordBinAnt[2] = WordBin[2];
		pWordBinAnt[3] = WordBin[3];

		return _4UintColTo16Pixel(pOrig);

	case '2': // Mode OFB.  (Zo = IV), Zi = EK(Zi-1), i >= 1. (Yi = Zi XOR Xi), i >= 1
		pWordBinAnt = EncrypterAES(pWordBinAnt);
		pOrig = uintXOR(pWordBinAnt, WordBin);
		return _4UintColTo16Pixel(pOrig);
		break;

	case '3': // Mode CFB. (Yo=IV), Zi = EK(Yi-1), i >= 1, Yi= Zi XOR Xi, i >= 1.

		pOrig = uintXOR(EncrypterAES(pWordBinAnt), WordBin);

		pWordBinAnt[0] = WordBin[0];
		pWordBinAnt[1] = WordBin[1];
		pWordBinAnt[2] = WordBin[2];
		pWordBinAnt[3] = WordBin[3];

		return _4UintColTo16Pixel(pOrig);
		break;
	}

	return _4UintColTo16Pixel(WordBin);
}

uint* DecrypterAES(const uint WordBin[4])
{
	int i;
	//uint *pOrig = new uint[4];
	uint* pOrig;
	allocation_tableau(pOrig, uint, 4);
	pOrig[0] = WordBin[0]; pOrig[1] = WordBin[1]; pOrig[2] = WordBin[2]; pOrig[3] = WordBin[3];

	AddRound(pOrig, RoundKey[10]);		//	ShowBlock("AddRound", WordBin);

	InvShiftRow(pOrig);					//	ShowBlock("ShiftRow", WordBin);

	InvSubKey(pOrig);						//	ShowBlock("SubKey",   WordBin);

// Neuf boucles pour la cl�de 128 bits.
	for (i = 1; i < 10; i++) {

		AddRound(pOrig, RoundKey[10 - i]);	//	ShowBlock("AddRound", WordBin);

		InvMixColumn(pOrig);				//	ShowBlock("MixColumn",WordBin);

		InvShiftRow(pOrig);				//	ShowBlock("ShiftRow", WordBin);

		InvSubKey(pOrig);					//	ShowBlock("SubKey",   WordBin);
	}

	AddRound(pOrig, RoundKey[0]);			//	ShowBlock("AddRound", WordBin);

	return pOrig;
}

void ShiftRow(uint WBinIn[4])
{
	// Cette fonction: Faire les d�alages des lignes 1, 2 et 3, On a 4 lignes (0 �3).
	OCTET oct[4] = { 0 }, i;

	for (i = 0; i < 4; i++)
		oct[i] = GETOCTET(WBinIn[i], 1); // Ligne 1

	PUTOCTET(WBinIn[0], oct[1], 1);
	PUTOCTET(WBinIn[1], oct[2], 1);
	PUTOCTET(WBinIn[2], oct[3], 1);
	PUTOCTET(WBinIn[3], oct[0], 1);

	for (i = 0; i < 4; i++)
		oct[i] = GETOCTET(WBinIn[i], 2); // Ligne 2
	PUTOCTET(WBinIn[0], oct[2], 2);
	PUTOCTET(WBinIn[1], oct[3], 2);
	PUTOCTET(WBinIn[2], oct[0], 2);
	PUTOCTET(WBinIn[3], oct[1], 2);

	for (i = 0; i < 4; i++)
		oct[i] = GETOCTET(WBinIn[i], 3); // Ligne 3
	PUTOCTET(WBinIn[0], oct[3], 3);
	PUTOCTET(WBinIn[1], oct[0], 3);
	PUTOCTET(WBinIn[2], oct[1], 3);
	PUTOCTET(WBinIn[3], oct[2], 3);
}

void InvShiftRow(uint WBinIn[4])
{
	// Cette fonction: D�aire que ShiftRow a fait.
	OCTET oct[4] = { 0 }, i;

	for (i = 0; i < 4; i++)
		oct[i] = GETOCTET(WBinIn[i], 1); // Ligne 1

	PUTOCTET(WBinIn[0], oct[3], 1);
	PUTOCTET(WBinIn[1], oct[0], 1);
	PUTOCTET(WBinIn[2], oct[1], 1);
	PUTOCTET(WBinIn[3], oct[2], 1);

	for (i = 0; i < 4; i++)
		oct[i] = GETOCTET(WBinIn[i], 2); // Ligne 2
	PUTOCTET(WBinIn[0], oct[2], 2);
	PUTOCTET(WBinIn[1], oct[3], 2);
	PUTOCTET(WBinIn[2], oct[0], 2);
	PUTOCTET(WBinIn[3], oct[1], 2);

	for (i = 0; i < 4; i++)
		oct[i] = GETOCTET(WBinIn[i], 3); // Ligne 3
	PUTOCTET(WBinIn[0], oct[1], 3);
	PUTOCTET(WBinIn[1], oct[2], 3);
	PUTOCTET(WBinIn[2], oct[3], 3);
	PUTOCTET(WBinIn[3], oct[0], 3);
};

void MixColumn(uint WBinIn[4])
{
	// Cette fonction: Faire un multiplication Galois de chaque colonne par la matrice MatMixCol. 
	OCTET i;
	OCTET LinMat;
	OCTET k;
	const uint nPrime = 283;
	uint nAux[4] = { 0 }, WBinCop[4] = { 0 };
	OCTET oct1, oct2;

	for (i = 0; i < 4; i++) {

		WBinCop[i] = WBinIn[i];
		for (LinMat = 0; LinMat < 4; LinMat++) {

			for (k = 0; k < 4; k++) {

				oct1 = GETOCTET(WBinCop[i], k);
				oct2 = GETOCTET(MatMixCol[LinMat], k);

				// Comme la plus grande valeur dans MatMixCol est trois. � est la mani�e plus simple de Galois.
				switch (oct2) {
				case 1:
					nAux[k] = oct1;					// Multiplication par 1
					break;
				case 2:
					nAux[k] = oct1 << 1;			// Multiplication par 2
					break;
				case 3:
					nAux[k] = (oct1 << 1) ^ oct1;	// Multiplication par 3
				}

				// Pour les octets avec bits d�ord�, on aplique XOR avec le premier.
				if (nAux[k] > 0xff)
					nAux[k] ^= nPrime;
			}
			oct1 = nAux[0] ^ nAux[1] ^ nAux[2] ^ nAux[3];

			PUTOCTET(WBinIn[i], oct1, LinMat);
		}
	}
}

void InvMixColumn(uint WBinIn[4])
{
	// Cette fonction: Faire une vraie multip.Galois de chaque colonne par la matrice InvMatMixCol.
	OCTET i;
	OCTET k;
	const uint nPrime = 283;
	uint nAux[4] = { 0 }, WBinCop[4] = { 0 };
	OCTET oct1, oct2, LinMat;

	for (i = 0; i < 4; i++) {

		WBinCop[i] = WBinIn[i];
		for (LinMat = 0; LinMat < 4; LinMat++) {

			for (k = 0; k < 4; k++) {
				// La matrice InvMatMixCol a des valeurs plus grandes que trois, donc on utilise le Galois.
				oct1 = GETOCTET(WBinCop[i], k);
				oct2 = GETOCTET(InvMatMixCol[LinMat], k);

				if (oct1 < 2 || oct2 < 2)
					// Si la valeur est z�o ou une jamais va d�order.
					nAux[k] = oct1 * oct2;
				else
					nAux[k] = GaloisMultAES(oct1, oct2);

			}
			oct1 = nAux[0] ^ nAux[1] ^ nAux[2] ^ nAux[3];

			PUTOCTET(WBinIn[i], oct1, LinMat);
		}
	}
}

void _32HexTo4UintCol(const OCTET c[32], uint WordBin[4])
{
	int i; int j;
	// Cette fonction: Entre une bloque de 32 octet hexad�imal et sort 4 uint par colonne.
	for (i = 0; i < 7; i += 2)
		for (j = 0; j < 4; j++) {
			WordBin[(int)(i / 2)] = (WordBin[(int)(i / 2)] << 4) | hexa2uc(c[8 * j + i]);
			WordBin[(int)(i / 2)] = (WordBin[(int)(i / 2)] << 4) | hexa2uc(c[8 * j + i + 1]);
		}
}

void _64HexTo8UintCol(const OCTET c[64], uint WordBin[8])
{
	int i; int j;

	for (i = 0; i < 7; i += 2)
		for (j = 0; j < 8; j++) {
			WordBin[(int)(i / 2)] = (WordBin[(int)(i / 2)] << 4) | hexa2uc(c[8 * j + i]);
			WordBin[(int)(i / 2)] = (WordBin[(int)(i / 2)] << 4) | hexa2uc(c[8 * j + i + 1]);
		}
}

uint GetS_BOX(uint c)
{
	// Cette fonction: Prendre chaque valeur dans S_BOX pour chaque octet du uint.
	uint WordBin = 0;
	OCTET oAux;
	OCTET i;
	for (i = 0; i < 4; i++) {
		// Ce MACRO prendre le octet 'i' dans le uint 'c'.
		oAux = GETOCTET(c, i);
		oAux = S_BOX[oAux >> 4][oAux & 0xf];  // Prendre ligne et colonne dans S_BOX.
// Ce MACRO mettre le nouvel octet  'oAux' sur la place 'i' dans uint 'WordBin'.
		PUTOCTET(WordBin, oAux, i);
	}

	return WordBin;
}

uint InvGetS_BOX(uint c)
{
	// Cette fonction: Faire le contraire de GetS_BOX.
	uint WordBin = 0;
	OCTET oAux;
	OCTET i;
	for (i = 0; i < 4; i++) {
		oAux = GETOCTET(c, i);
		PUTOCTET(WordBin, InvS_BOX[oAux], i);
	}

	return WordBin;
}

//------------------------------------------------------------
// Fonctions William Puech
//------------------------------------------------------------
// transformation d'un symbole hexadecimal en entier de 0 a 15
unsigned char hexa2uc(char c) {
	switch (c) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': return 10;
	case 'b': return 11;
	case 'c': return 12;
	case 'd': return 13;
	case 'e': return 14;
	case 'f': return 15;
	case 'A': return 10;
	case 'B': return 11;
	case 'C': return 12;
	case 'D': return 13;
	case 'E': return 14;
	case 'F': return 15;
	default: printf("code hexadecimal '%c' incorrect\n", c);
		exit(0);
	}
}

uint GaloisMultAES(OCTET v1, OCTET v2)
{
	// Cette fonction: Faire la multiplication de Galois et le décalage avec le premier 283.

	/*
	For example, multiplying the binary string 11001010 by 3 within
	this Galois Field works like this:

			10100011
		  *     1110
		 -----------
		 10100011
		  10100011
		   10100011
		 -----------
		 11011010010  (XOR instead of addition)
		 100011011    (this is XORed, instead of subtracting 283)
		 -----------
		  1010111110
		  100011011   (this is XORed, instead of subtracting 283)
		  ----------
			10001000
	*/

	// Multiplication de Galois---------------------------------------
	OCTET x = 7;                                                  //
	while (!GETBIT(v2, x)) x--;                                 //
	uint Res = (v1 << x);                                       //
	while (--x) Res ^= (v1 * GETBIT(v2, x)) << x;              //
	Res ^= (v1 * GETBIT(v2, 0));                               //
//----------------------------------------------------------------

// Xor avec le premier 283 d�al��gauche
	uint nPrime = 283;
	x = 11;
	while (!GETBIT(Res, x)) x--;

	while (x > 7) {
		if (GETBIT(Res, x))
			Res ^= (nPrime << (x - 8));
		x--;
	}

	return Res;
}

// PRECONDITION : a is a multiple of 8
OCTET* binaryToOCTET(const vector<bool>& a, int* nbOctets) {
	const int bitSize = 8;
	*nbOctets = a.size() / bitSize; 
	
	OCTET* cstream = new OCTET[*nbOctets];

	for (size_t i = 0; i < a.size(); i += bitSize) {
		OCTET c = 0;

		for (int j = 0; j < bitSize; j++) {
			if (a[i + j])  c |= 1 << j;
		}

		cstream[i / bitSize] = c;
	}

	return cstream;
}

vector<bool> octetToBinary(OCTET* a, int nbOctets) {
	vector<bool> binary;

	for (int i = 0; i < nbOctets; i++) {
		for (int j = 0; j < 8; j++) {
			binary.push_back(((a[i] >> j) & 1) == 1);
		}
	}

	return binary;
}

vector<bool> stringToBinary(const string& m) {
	const int bitSize = 8;
	vector<bool> a;

	for (size_t i = 0; i < m.size(); i++) {
		bitset<bitSize> charBits = bitset<bitSize>(m[i]);
		for (size_t j = 0; j < charBits.size(); j++) {
			if (charBits[j] & 1) a.push_back(1);
			else a.push_back(0);
		}
	}

	return a;
}

void readKeyIV(OCTET* oCle, char* nom_Cle, OCTET* oIV, char* nom_IV) {
	FILE* f_Cle;
	FILE* f_IV;

	// Verification de la clef
	if ((f_Cle = fopen(nom_Cle, "rb")) == NULL)
	{
		printf("\nPas d'acces en lecture sur le fichier de la Cle %s \n", nom_Cle);
		exit(EXIT_FAILURE);
	}

	if ((fread((OCTET*)oCle, sizeof(OCTET), 64, f_Cle)) > 64)
	{
		printf("\nErreur de lecture de la Cle \n");
		exit(EXIT_FAILURE);
	}

	fclose(f_Cle);

	// IV verification
	if ((f_IV = fopen(nom_IV, "rb")) == NULL)
	{
		printf("\nPas d'acces en lecture sur le fichier de la IV %s \n", nom_IV);
		exit(EXIT_FAILURE);
	}

	if ((fread((OCTET*)oIV, sizeof(OCTET), 32, f_IV)) > 32)
	{
		printf("\nErreur de lecture de la IV \n");
		exit(EXIT_FAILURE);
	}

	fclose(f_IV);
}

void setIV(OCTET* oCle, OCTET* oIV) {
	OCTET x;

	// Verifie si le MODE ait besoin de un vecteur de initialisation
	if (Type_mode != '0')
	{
		_32HexTo4UintCol(oIV, uintIV);
		pWordBinAnt = uintIV;
	}
}

/****************************************************MANTISSA FUNCTIONS******************************************************************/

typedef union {
	float f;
	struct
	{
		unsigned int mantissa : 23;
		unsigned int exponent : 8;
		unsigned int sign : 1;

	} raw;
} floatDec;

vector<bool> getMantissa(const float& f) {
	vector<bool> mantissa(MANT_SIZE);

	floatDec fUnion;
	fUnion.f = f;

	unsigned int m = fUnion.raw.mantissa;

	// LSB --> MSB
	for (int i = 0; i < MANT_SIZE; i++)
	{
		int mod = m % 2;
		mantissa[i] = (mod == 1);
		m = m / 2;
	}

	return mantissa;
}

vector<bool> sortBits(const vector<vector<bool>>& bitsToSort) {
	vector<bool> sortedBits;

	// LSB --> MSB
	for (int i = 0; i < MANT_SIZE; i++) {       // For each n bit
		for (int j = 0; j < bitsToSort.size(); j++) {       // in each mantissa
			sortedBits.push_back(bitsToSort[j][i]);     // Push the next bit to the sorted list
		}
	}

	return sortedBits;
}

unsigned int binaryToDecimal(const vector<bool>& a) {
	unsigned int e = 0;
	unsigned int p = 1;

	for (int i = 0; i < a.size(); i++) {
		if (a[i]) e = e + p;
		p = p * 2;
	}

	return e;
}

vector<bool> decimalToBinary(uint *w, const int size) {
	vector<bool> a;
	uint *e = new uint[4];
	for (int i = 0; i < 4; i++) e[i] = w[i];

	// LSB --> MSB
	for (int j = 0; j < 4; j++) {
		for (int i = 0; i < 32; i++)
		{
			int mod = e[j] % 2;
			a.push_back(mod == 1);
			e[j] = e[j] / 2;
		}
	}

	return a;
}

void replaceMantissa(float& f, const vector<bool>& m) {
	unsigned int mant = binaryToDecimal(m);

	floatDec fUnion;
	fUnion.f = f;
	fUnion.raw.mantissa = mant;

	f = fUnion.f;
}

void replaceVerticesMantissas(Eigen::MatrixXd& V, int index, const vector<vector<bool>>& m, int sizeOfBlock) {

	for (int j = 0; j < sizeOfBlock; j++) {
		unsigned int ind = index + j;
		if (ind < V.rows()) {
			for (int i = 0; i < 3; i++) {
				//cout << j << " " << i << endl;
				unsigned int mInd = j * 3 + i;
				float f = (float)V(ind, i);
				replaceMantissa(f, m[mInd]);

				V(ind, i) = f;
			}
		}
	}
}

/****************************************************BLOCKS******************************************************************/
// Returns unpadded blocks of size nbPerBlock
vector<vector<bool>> generateBlocks(const int nbPerBlock, const Eigen::MatrixXd* V) {
	vector<vector<bool>> blocks;

	for (int i = 0; i < V->rows(); i += nbPerBlock) {     // For each vertex in the object
		//if (i + nbPerBlock < V->rows()) {
			vector<vector<bool>> block;
			for (int j = 0; j < nbPerBlock; j++) {      // Create a block of nbPerBlock
				for (int k = 0; k < 3; k++) {       // Add each coordinate
					if (i + j < V->rows()) {       // If the coordinate exists
						vector<bool> mant = getMantissa((*V)(i + j, k));
						block.push_back(mant);
					}
					/*else {       // Else pad it
						vector<bool> mant(23, 0);
						block.push_back(mant);
					}*/
				}
				// cout << i + j << " ";
			}
			blocks.push_back(sortBits(block));
			//cout << endl;
		//}
	}

	return blocks;
}

/*
* The vector of points should start with the first index of the master key.
* eg. For a mask: (MSB) 3332221111000000-1-1-1...
* 0: master key
* -1: leave in clear
*/
vector<int> generateMask(const vector<int>* indexes, const int bsize) {
	int mod = bsize * 3;        // the total block size is the nb of coords per block * mantissa size * 3 (3 for the coords)
	vector<int> mask(MANT_SIZE * mod, -1);

	for (int i = 0; i < indexes->size(); i++) {
		for (int j = (*indexes)[i] * mod; j < MANT_SIZE * mod; j++) {
			mask[j] = i;
		}
	}

	return mask;
}

void printIntArray(vector<int>* a) {
	for (int i = 0; i < a->size(); i++) {
		cout << (*a)[i] << " ";
	}
	cout << endl;
}

void printVecBoolArray(vector<vector<bool>>* a) {
	for (int i = 0; i < a->size(); i++) {
		for (int j = 0; j < (*a)[i].size(); j++) {
			cout << (*a)[i][j];
		}
		cout << endl;
	}
}

// Divide a single block into multiple blocks (the number of keys + 1)
vector<vector<bool>> divideBlock(const vector<bool>& block, const vector<int>& mask, const int nbKeys) {
	vector<vector<bool>> divBlock(nbKeys + 1);    // There are nbKey blocks + 1

	for (int i = 0; i < block.size(); i++) {
		divBlock[mask[i] + 1].push_back(block[i]);   // The index corresponds to the mask number + 1 (-1 : block 0, master : block 1 etc...)
	}

	return divBlock;
}

// To be used to pad the blocks already divided into their blocks to be encrypted
/*void padBlocks(vector<vector<bool>>& divBlocks, int desiredSize) {
	for (int i = 0; i < divBlocks.size(); i++) {
		for (int j = divBlocks[i].size(); j < desiredSize; j++) {
			divBlocks[i].push_back(0);
		}
	}
}*/

vector<bool> padBlock(vector<bool> b, int desiredSize) {
	for (int j = b.size(); j < desiredSize; j++) {
		b.push_back(0);
	}

	return b;
}

// Return a flux of non-padded blocks
vector<vector<bool>> createBlockStreams(const vector<vector<bool>>& blocks, const vector<int>& mask, const vector<int>& lastMask, const int nbKeys, const int keySize) {
	vector<vector<bool>> divBlock(nbKeys + 1);
	
	for (int i = 0; i < blocks.size() - 1; i++) {   // For each block (except the smaller, last block)
		vector<vector<bool>> decomp = divideBlock(blocks[i], mask, nbKeys);     // decompose the block
		// padBlocks(decomp, keySize);		// pad the block

		for (int j = 0; j <= nbKeys; j++) {
			divBlock[j].insert(divBlock[j].end(), decomp[j].begin(), decomp[j].end());      // add each decomposition to the end
		}
	}

	// For the last block
	vector<vector<bool>> decomp;
	if(lastMask.size()>0) decomp = divideBlock(blocks.back(), lastMask, nbKeys);     // decompose the block
	else decomp = divideBlock(blocks.back(), mask, nbKeys);

	for (int j = 0; j <= nbKeys; j++) {
		divBlock[j].insert(divBlock[j].end(), decomp[j].begin(), decomp[j].end());      // add each decomposition to the end
	}

	return divBlock;
}

/*************************************STREAMS******************************************************/

/*
* Separate the mesh into streams for keys.
* Returns the nb of keys + 1 streams (the keys + the clear)
*/
vector<vector<bool>> generateStreams(const Eigen::MatrixXd* V, const int nbKeys, const vector<int>* mask) {
	vector<vector<bool>> flux(nbKeys + 1);

	for (int i = 0; i < V->rows(); i++) {
		for (int j = 0; j < 3; j++) {
			vector<bool> mantissa = getMantissa((*V)(i, j));    // Get the mantissa for each x,y,z of each vertex
			for (int i = 0; i < mask->size(); i++) {     // For each bit in the mantissa
				if ((*mask)[i] != -1) {        // If it's not supposed to be left in clear
					flux[(*mask)[i]].push_back(mantissa[i]);     // Place it in the correct key column
				}
				else {
					flux.back().push_back(mantissa[i]);     // The bits to be left in clear
				}
			}
		}
	}

	return flux;
}

/*
* The vector of points should start with the first index of the master key.
* eg. For a mask: (MSB) 3332221111000000-1-1-1...
* 0: master key
* -1: leave in clear
*/
vector<int> generateMaskSingleBlock(const vector<int>* indexes) {
	vector<int> mask(23, -1);

	for (int i = 0; i < indexes->size(); i++) {
		for (int j = (*indexes)[i]; j < 23; j++) {
			mask[j] = i;
		}
	}

	return mask;
}



// Unshuffle a block
vector<vector<bool>> unshuffleBits(const vector<bool>& bitsToSort) {
	vector<vector<bool>> unshuffled;
	int nbOfCoordinates = bitsToSort.size() / MANT_SIZE;

	// LSB --> MSB
	for (int i = 0; i < nbOfCoordinates; i++) {       // For each n bit
		vector<bool> mant(MANT_SIZE);
		for (int j = 0; j < MANT_SIZE; j++) {       // in each mantissa
			mant[j] = bitsToSort[j * nbOfCoordinates + i];
		}
		unshuffled.push_back(mant);
	}

	return unshuffled;
}


/*
* Decompose the padded flux into the original blocks.
* encryptionSize: 128, 256 bits
*/
vector<vector<bool>> streamToBlocks(const vector<vector<bool>> &flux, const vector<int> mask, const vector<int> lastMask, int bitsPerBlock) {
	int nbBlocks = flux.back().size() / bitsPerBlock;
	vector<vector<bool>> blocks;

	int* maskIndexes = new int[flux.size()];
	for (int i = 0; i < flux.size(); i++) maskIndexes[i] = 0;

	for (int i = 0; i < nbBlocks; i++) {	// For each block to retrieve (execpt the last)
		vector<bool> block;
		/*for (int k = 1; k < flux.size(); k++) {
			maskIndexes[k] = encryptionSize * i;	// Advance the index to skip the padding (clear has no padding)
		}*/
		for (int j = 0; j < mask.size(); j++) {
			int mI = mask[j] + 1;		// The actual stream it belongs to
			block.push_back(flux[mI][maskIndexes[mI]]);		// Get the correct block
			maskIndexes[mI]++;	// Move to the next
		}
		blocks.push_back(block);
	}

	// For the last block
	if (lastMask.size() > 0) {
		vector<bool> block;
		for (int j = 0; j < lastMask.size(); j++) {
			int mI = lastMask[j] + 1;		// The actual stream it belongs to
			block.push_back(flux[mI][maskIndexes[mI]]);		// Get the correct block
			maskIndexes[mI]++;	// Move to the next
		}
		blocks.push_back(block);
	}

	return blocks;
}

/*
* Replace the mantissas with the encrypted flux
*/
void replaceMantissaWithStream(Eigen::MatrixXd &V, vector<vector<bool>>& decomp, const vector<int>& mask, const vector<int>& lastMask, int bsize, int bitSize) {
	vector<vector<bool>> blocks = streamToBlocks(decomp, mask, lastMask, bsize*bitSize);

	for (int i = 0; i < blocks.size(); i++) {
		vector<vector<bool>> unshuffled = unshuffleBits(blocks[i]);     // Separate into coordinates
		replaceVerticesMantissas(V, i * bsize, unshuffled, blocks[i].size()/(MANT_SIZE*3));
	}
}

/*
* Replace the mantissas with the encrypted flux
*/
void replaceMantissaWithFlux(Eigen::MatrixXd* V, vector<vector<bool>>* flux, const vector<int>* mask) {
	vector<int> indexes(flux->size(), 0);   // indexes to keep track of where we are in each flux

	for (int i = 0; i < V->rows(); i++) {   // For each vertex
		for (int j = 0; j < 3; j++) {       // For each coordinate
			vector<bool> coord; // Reconstruct the coordinate
			for (int m = 0; m < mask->size(); m++) {
				int fluxNumber = (*mask)[m];
				if (fluxNumber != -1) {
					coord.push_back((*flux)[fluxNumber][indexes[fluxNumber]]);
					indexes[fluxNumber]++;
				}
				else {
					coord.push_back((*flux).back()[indexes.back()]);
					indexes.back()++;
				}
			}
			float f = (float)(*V)(i, j);
			replaceMantissa(f, coord);
			(*V)(i, j) = f;
		}
	}
}

OCTET* EncryptAES_IV(const uint c[4], uint* word)
{
	// Convert pixels to words
	uint WordBin[4];
	for (int i = 0; i < 4; i++) WordBin[i] = c[i];
	uint* pUint;
	allocation_tableau(pUint, uint, 4);
	

	int i;
	AddRound(WordBin, RoundKey[0]);

	// Rounds
	for (i = 1; i < 14; i++) {
		SubKey(WordBin);
		ShiftRow(WordBin);
		MixColumn(WordBin);
		AddRound(WordBin, RoundKey[i]);
	}

	SubKey(WordBin);
	ShiftRow(WordBin);
	AddRound(WordBin, RoundKey[14]);

	for (int i = 0; i < 4; i++) word[i] = WordBin[i];

	return _4UintColTo16Pixel(WordBin);		// Return the word bin as bytes
}

// A single round of AES (adapted from EncrypterAES)
OCTET* EncryptAES_Single(const OCTET c[16])
{
	// Convert pixels to words
	uint WordBin[4] = { 0 };
	uint* pUint;
	allocation_tableau(pUint, uint, 4);
	_16PixelTo4UintHex(c, WordBin);

	int i;
	AddRound(WordBin, RoundKey[0]);

// Rounds
	for (i = 1; i < 14; i++) {
		SubKey(WordBin);				
		ShiftRow(WordBin);				
		MixColumn(WordBin);				
		AddRound(WordBin, RoundKey[i]);	
	}

	SubKey(WordBin);					
	ShiftRow(WordBin);					
	AddRound(WordBin, RoundKey[14]);	

	return _4UintColTo16Pixel(WordBin);		// Return the word bin as bytes
}

void sha256(const std::string& unhashed, std::string& hashed)
{
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int lengthOfHash = 0;

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, unhashed.c_str(), unhashed.length());
	EVP_DigestFinal_ex(ctx, hash, &lengthOfHash);
	std::stringstream ss;
	for (unsigned int i = 0; i < lengthOfHash; ++i) ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

	hashed = ss.str();
	EVP_MD_CTX_free(ctx);
}

string binaryToString(const vector<bool>& a) {
	string s = "";
	const int bitSize = 8;

	for (size_t i = 0; i < a.size(); i += bitSize) {
		bitset<bitSize> charBits;
		for (size_t j = 0; j < bitSize; j++) {
			if (i + j < a.size() && a[i + j]) charBits[j] = 1;
			else charBits[j] = 0;
		}
		s += (char)(charBits.to_ulong());
	}

	return s;
}

/*
* Generate the next key
* Takes the previous block 0 + its encryption
*/
string generateKey(vector<bool> prevBlock0, vector<bool> prevBlock0encr) {
	prevBlock0.insert(prevBlock0.end(), prevBlock0encr.begin(), prevBlock0encr.end());

	string shaInput = binaryToString(prevBlock0);
	string shaOutput;

	sha256(shaInput, shaOutput);

	return shaOutput;
}

OCTET* octetXOR(OCTET* ptext, OCTET* ctext, int size) {
	OCTET* result = new OCTET[size];
	for (int i = 0; i < size; i++) {
		result[i] = ptext[i] ^ ctext[i];
	}

	return result;
}

// a is the smaller vector
vector<bool> binaryXOR(vector<bool>& a, vector<bool>& b) {
	vector<bool> x;
	for (int i = 0; i < a.size(); i++) {
		x.push_back(a[i] ^ b[i]);
	}

	return x;
}

/*
* Divide into blocks according to the key stream
*/
vector<vector<bool>> divideIntoBlocks(vector<bool>& plaintext, int bsize, int bitsSize) {
	int cbSize = bsize * bitsSize;
	vector<vector<bool>> currentBlocks;

	for (int i = 0; i < plaintext.size(); i+=cbSize) {
		vector<bool> cb;
		for (int j = 0; j < cbSize; j++) {
			if(i+j < plaintext.size()) cb.push_back(plaintext[i+j]);	// Protection for the last block
		}
		currentBlocks.push_back(cb);
	}

	return currentBlocks;
}

void stringToOctet(string s, int size, OCTET* o) {
	const char* c_array = s.c_str();

	for (int i = 0; i < size; i++) o[i] = c_array[i];
}

/*
* Encrypts a single key stream (unpadded)
* bitsSize: the number of bits per block in this key
* encSize: nb of bytes
*/
vector<vector<bool>> hierarchicalEncryption(vector<bool>& plaintext, OCTET* oCle, OCTET* oIV, int bsize, int bitsSize, int encSize) {
	vector<vector<bool>> encryption;
	int nbOctets;

	vector<vector<bool>> currentBlock = divideIntoBlocks(plaintext, bsize, bitsSize);		// Divide into current blocks
	
	uint encIVword[4];
	OCTET* oIV_e = EncryptAES_IV(uintIV, encIVword);		// Encrypt the oIV with a single round of AES (takes 16 bits)
	vector<bool> binaryEncryption = octetToBinary(oIV_e, 16);		// convert back to bits 
	encryption.push_back(binaryXOR(currentBlock[0], binaryEncryption));		// Perform and xor with oIV' and B0 to get B0' encryption

	vector<bool> oIVbinary = decimalToBinary(uintIV, 32);

	string nextIV = generateKey(oIVbinary, binaryEncryption);
	stringToOctet(nextIV, 32, oIV);

	string nextKey = generateKey(currentBlock[0], encryption[0]);
	stringToOctet(nextKey, encSize/4, oCle);

	/*
	* Current block: Bi
	* encryption[i - 1]: Bi-1'
	* b_prec_enc: Bi-1''
	*/
	for (int i = 1; i < currentBlock.size(); i++) {
		vector<bool> paddedEnc = padBlock(encryption[i - 1], 128);		// Pad Bi-1'
		OCTET* ptext = binaryToOCTET(paddedEnc, &nbOctets);		// Convert Bi-1' padded to bytes
		OCTET* ctext = EncryptAES_Single(ptext);		// Encrypt Bi-1' with a single AES round
		vector<bool> b_prec_enc = octetToBinary(ctext, nbOctets);
		encryption.push_back(binaryXOR(currentBlock[i], b_prec_enc));		// Perform an xor with Bi-1'' and Bi to get Bi'
	}

	return encryption;
}

vector<vector<bool>> hierarchicalDecryption(vector<bool>& plaintext, OCTET* oCle, OCTET* oIV, int bsize, int bitsSize, int encSize) {
	vector<vector<bool>> decryption;
	int nbOctets; 

	vector<vector<bool>> currentBlock = divideIntoBlocks(plaintext, bsize, bitsSize);		// Divide into current blocks

	// First round
	uint encIVword[4];
	OCTET* oIV_e = EncryptAES_IV(uintIV, encIVword);		// Encrypt the oIV with a single round of AES (takes 16 bits)
	vector<bool> binaryEncryption = octetToBinary(oIV_e, 16);		// convert back to bits 
	decryption.push_back(binaryXOR(currentBlock[0], binaryEncryption));		// Perform and xor with oIV' and B0' to get B0 

	vector<bool> oIVbinary = decimalToBinary(uintIV, 32);
	string nextIV = generateKey(oIVbinary, binaryEncryption);
	stringToOctet(nextIV, 32, oIV);


	/*
	* Current block[i - 1]: Bi-1'
	* Current block[i]: Bi'
	* b_prec_enc: Bi-1''
	*/

	for (int i = 1; i < currentBlock.size(); i++) {
		vector<bool> paddedEnc = padBlock(currentBlock[i - 1], 128);		// Pad Bi-1' (now stored in current block)
		OCTET* ptext = binaryToOCTET(paddedEnc, &nbOctets);
		OCTET* ctext = EncryptAES_Single(ptext);		// Encrypt Bi-1' with a single AES round
		vector<bool> b_prec_enc = octetToBinary(ctext, nbOctets);
		decryption.push_back(binaryXOR(currentBlock[i], b_prec_enc));		// Perform an xor with Bi-1'' and Bi' to get Bi
	}

	string nextKey = generateKey(decryption[0], currentBlock[0]);
	stringToOctet(nextKey, encSize / 4, oCle);

	return decryption;
}

// Encrypt EVERYTHING
void encryptStreamsV2(vector<vector<bool>>& keyStreams, OCTET* oCle, OCTET* oIV, int bsize, int bitSize, int encSize, OCTET** keyList, OCTET** ivList) {

	for (int keyIndex = 1; keyIndex < keyStreams.size(); keyIndex++) {	// Index 0 is for untouched LSB

		KeySchedule(oCle, RoundKey);
		setIV(oCle, oIV);		// Reinit the key

		for (int i = 0; i < encSize / 4; i++) keyList[keyIndex - 1][i] = oCle[i];
		for (int i = 0; i < 32; i++) ivList[keyIndex - 1][i] = oIV[i];
		

		cout << "Key: ";
		for (int i = 0; i < encSize / 4; i++) cout << oCle[i];
		cout << endl;

		cout << "IV: ";
		for (int i = 0; i < 32; i++) cout << oIV[i];
		cout << endl;

		vector<vector<bool>> encryption_stream = hierarchicalEncryption(keyStreams[keyIndex], oCle, oIV, bsize, bitSize, encSize);

		int keyStreamIndex = 0;
		for (int i = 0; i < encryption_stream.size(); i++) {		// Replace the key stream with the encryption
			for (int j = 0; j < encryption_stream[i].size(); j++) {
				keyStreams[keyIndex][keyStreamIndex] = encryption_stream[i][j];
				keyStreamIndex++;
			}
		}
	}
}

void decryptStreamsV2(const int accessLevel, vector<vector<bool>>& keyStreams, OCTET* oCle, OCTET* oIV, int bsize, int bitSize, int encSize, OCTET** keyList, OCTET** ivList) {

	for (int keyIndex = accessLevel + 1; keyIndex < keyStreams.size(); keyIndex++) {		// +1 to skip the bits left clear
		KeySchedule(keyList[keyIndex - 1], RoundKey);
		setIV(keyList[keyIndex - 1], ivList[keyIndex - 1]);		// Reinit the key

		cout << "Key: ";
		for (int i = 0; i < encSize / 4; i++) cout << oCle[i];
		cout << endl;

		cout << "IV: ";
		for (int i = 0; i < 32; i++) cout << oIV[i];
		cout << endl;

		vector<vector<bool>> decryption_stream = hierarchicalDecryption(keyStreams[keyIndex], oCle, oIV, bsize, bitSize, encSize);

		int keyStreamIndex = 0;
		for (int i = 0; i < decryption_stream.size(); i++) {		// Replace the key stream with the encryption
			for (int j = 0; j < decryption_stream[i].size(); j++) {
				keyStreams[keyIndex][keyStreamIndex] = decryption_stream[i][j];
				keyStreamIndex++;
			}
		}
	}
}



/*************************************************************/
int main()
{
	vector<string> possibleKeys;
	vector<string> possibleIV;

	/*********PARAMETERS************/
	int bpb = 3;		// Bits per block (alpha in the paper). Recommended value: 2 or 3 according to desired use.

	string rootFile = "C:\\Users\\Bianca\\Documents\\";
	string baseRoot = "Meshes\\Stanford\\";

	const char* keyFile = "C:\\Users\\Bianca\\Documents\\Hierarchical_Decryption\\Keys\\_Key_List.txt";
	const char* ivFile = "C:\\Users\\Bianca\\Documents\\Hierarchical_Decryption\\Keys\\_IV_List.txt";

	vector<string> meshes = { "bunny", "casting", "cow", "crank", "dragon", "horse", "hand", "rabbit", "venus", "Ramesses" };
	/******************************/

	char line[256];

	// Read the list of possible keys (key randomly chosen)
	FILE* fkey = fopen(keyFile, "r");
	while (fgets(line, sizeof(line), fkey)) {
		string s = "";
		for (int i = 0; i < 64; i++) s = s + line[i];
		possibleKeys.push_back(s);
	}

	// Read the list of possible IV (IV randomly chosen)
	FILE* fiv = fopen(ivFile, "r");
	while (fgets(line, sizeof(line), fiv)) {
		string s = "";
		for (int i = 0; i < 32; i++) s = s + line[i];
		possibleIV.push_back(line);
	}

	srand(0);

	const vector<vector<int>> startingIndexes{ {20, 21, 22}, { 17, 19, 21 }, { 14, 17, 20 }, {11, 15, 19}, {8, 13, 18} };

	for (int meshNb = 0; meshNb < meshes.size(); meshNb++) {
		const int bitSize = 3 * bpb;		// The number of bits per coordinate to encrypt
		const int bsize = 128 / bitSize;			// The block size
		vector<int> indexes = startingIndexes[bpb - 1]; // The starting indexes of each security level

		int index = rand() % 100;

		// Read mesh file
		Eigen::MatrixXd V;
		Eigen::MatrixXi F;

		string filename = rootFile + baseRoot + meshes[meshNb] + ".off";
		string outputName = rootFile + "Hierarchical_Decryption\\Test\\" + meshes[meshNb] + "_" + to_string(bpb) + "_enc.off";

		igl::readOFF(filename, V, F);

		OCTET* oCle; OCTET* oIV;
		allocation_tableau(oCle, OCTET, 65);
		allocation_tableau(oIV, OCTET, 33);

		for (int i = 0; i < 64; i++) {
			oCle[i] = possibleKeys[index][i];
		}

		for (int i = 0; i < 32; i++) {
			oIV[i] = possibleIV[index][i];
		}

		OCTET** keyList = new OCTET * [3];
		OCTET** ivList = new OCTET * [3];
		for (int i = 0; i < 3; i++) {
			keyList[i] = new OCTET[64];
			ivList[i] = new OCTET[33];
		}

		Type_mode = '3';

		vector<vector<bool>> blocks = generateBlocks(bsize, &V);
		vector<int> mask = generateMask(&indexes, bsize);
		int lastBlockSize = V.rows() % bsize;
		vector<int> lastMask = generateMask(&indexes, lastBlockSize);


		std::cout << "\nGenerating blocks...." << meshNb << endl;
		vector<vector<bool>> decomp = createBlockStreams(blocks, mask, lastMask, indexes.size(), 256);		// Single streams of blocks divided according to their access level

		// Encryption
		encryptStreamsV2(decomp, oCle, oIV, bsize, bitSize, 256, keyList, ivList);

		std::cout << "Replacing the coordinates...." << endl;
		replaceMantissaWithStream(V, decomp, mask, lastMask, bsize, bitSize);
		igl::writeOFF(outputName, V, F);

		// Decryption
		for (int accessLevel = 0; accessLevel < 3; accessLevel++) {
			vector<vector<bool>> decompCP;
			for (int i = 0; i < decomp.size(); i++) {
				vector<bool> dec;
				for (int j = 0; j < decomp[i].size(); j++) {
					dec.push_back(decomp[i][j]);
				}
				decompCP.push_back(dec);
			}

			std::cout << "\nDecrypting " << accessLevel << endl;
			decryptStreamsV2(accessLevel, decompCP, oCle, oIV, bsize, bitSize, 256, keyList, ivList);

			std::cout << "Replacing the coordinates...." << endl;
			replaceMantissaWithStream(V, decompCP, mask, lastMask, bsize, bitSize);

			string outputName2 = rootFile + "Hierarchical_Decryption\\Test\\" + meshes[meshNb] + "_" + to_string(bpb) + "_" + to_string(accessLevel) + ".off";
			igl::writeOFF(outputName2, V, F);
		}

	}

	return 0;
}
