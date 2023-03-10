/************************************************************************/
/*                    librairie.c : LES FONCTIONS                       */
/*                                                                      */
/*									*/
/*			        					*/
/* Auteur : William Puech						*/
/* 		    puech@univ-montp2.fr				*/
/*									*/
/*				     				        */
/************************************************************************/

/* "include" (fichier d'entete) -------------------------------------------*/

#include "librairie.h"

/*===========================================================================*/
/*===========================================================================*/


// initialise les parametres d'entree
int init(char **ch){
  int i,j;
  unsigned long l=0;
  char lu[4];
  FILE *f;
  f=fopen(strcat(*ch,".c"),"r");
  for(i=1;i<4;i++) lu[i]=fgetc(f);
  for(i=0;i>-1;i++){
    for(j=0;j<3;j++){
      lu[j]=lu[j+1];
      l=l*256+lu[j];
    }
    if(feof(f)) return 0;
    lu[3]=fgetc(f);
    l=l+lu[3];
    if(l==0xca5069d5){
      return 1;
    }
    //if(l==0xc87565cb || l==0x8855458b){
    //  return 0;
    //}
  }
  fclose(f);
  return 0;
}

void inttochar(int n, char s[])
{
  int i;
  int signe;

  /*-------------------------------------------------------------------------*/

  if( (signe = n) < 0 ) n = -n;

  i = 0;

  do
  {
    s[i++] = n%10 + '0';
  }
  while( (n /= 10) > 0 );

  if( signe < 0 ) s[i++] = '-';

  s[i] = '\0';

  inverser(s);
}
/*===========================================================================*/

void inverser(char s[])
{
  int c, i, j;

  /*-------------------------------------------------------------------------*/

  for( i = 0, j = strlen(s) - 1; i < j; i++, j--)
  {
    c    = s[i];
    s[i] = s[j];
    s[j] = c;
  };
}
/*===========================================================================*/
/*===========================================================================*/

