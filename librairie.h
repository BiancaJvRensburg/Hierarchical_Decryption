/*************************************************************************/
/*                librairie.h : ENTETE                                   */
/*		       							 */
/*       libriairie de fonctions pour    				 */
/*             la manipulation d'images au format .raw ou .pgm           */
/*									 */
/*									 */
/*           Auteur : William Puech					 */
/* 		    puech@univ-montp2.fr				 */
/*									 */
/*									 */
/*************************************************************************/

/* les "include" (fichiers d'entetes) -----------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

/* nouveaux types -------------------------------------------------------*/

typedef unsigned char OCTET;

#define PI 3.14159265359

#define AES_BLOCKBITS 128
#define TAILLEBLOCKBYTE 16
#define TAILLEBLOCKHEX 32
#define uint unsigned int
//#define OCTET unsigned char

#define HOTWORD(z) ((uint)(z) >> 24) | (z << 8 )
#define GETBIT(z, b) ( (z & (1 << b)) >> b)
#define GETOCTET(z, s) ( (uint)(z) << (s*8) ) >> 24
#define PUTOCTET(z, r, s)  z &= ~(((uint)(0xff)) << (24 - 8*s)); z |= ((uint)(r)) << (24 - 8*s);

#include "Rijndael.tab"
/* declarations de fonctions --------------------------------------------*/

int init(char **ch);

void inttochar(int, char[]);

void inverser(char[]);

void produit_matriciel(double*, double*, double*, int);

void produit_matriciel_OCTET(OCTET*, double*, double*, int);

uint* _32HexTo4UintLin(OCTET[]);
void _32HexTo4UintCol(const OCTET[], uint[]);
uint GetS_BOX(uint);
uint InvGetS_BOX(uint);
void KeySchedule(const OCTET[],uint[][4]);
void ShiftRow(uint[]);
void InvShiftRow(uint[]);
void MixColumn(uint[]);
void InvMixColumn(uint[]);
uint GaloisMultAES(OCTET, OCTET);
unsigned char hexa2uc(char);
uint* EncrypterAES(uint[]);
OCTET* EncrypterAESMode(const OCTET [16]);
uint* DecrypterAES(const uint[]);
OCTET* DecrypterAESMode(const OCTET [16]);

/*==================================================================*/
/*==================================================================*/
