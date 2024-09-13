/*
Develop by Alberto
email: albertobsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "oldbloom/oldbloom.h"
#include "bloom/bloom.h"
#include "util.h"
#include "hashing.h"

#include "gmp256k1/GMP256K1.h"
#include "gmp256k1/Point.h"
#include "gmp256k1/Int.h"
#include "gmp256k1/IntGroup.h"
#include "gmp256k1/Random.h"


#if defined(_WIN64) && !defined(__CYGWIN__)
#include "getopt.h"
#include <windows.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>
#endif

#ifdef __unix__
#ifdef __CYGWIN__
#else
#include <linux/random.h>
#endif
#endif

#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define CRYPTO_ETH 2
#define CRYPTO_ALL 3

#define MODE_XPOINT 0
#define MODE_ADDRESS 1
#define MODE_BSGS 2
#define MODE_RMD160 3
#define MODE_PUB2RMD 4
#define MODE_MINIKEYS 5
#define MODE_VANITY 6

#define SEARCH_UNCOMPRESS 0
#define SEARCH_COMPRESS 1
#define SEARCH_BOTH 2

uint32_t  THREADBPWORKLOAD = 1048576;

struct checksumsha256	{
	char data[32];
	char backup[32];
};

struct bsgs_xvalue	{
	uint8_t value[6];
	uint64_t index;
};

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
	char *rs;   //range start
	char *rpt;  //rng per thread
};

struct bPload	{
	uint32_t threadid;
	uint64_t from;
	uint64_t to;
	uint64_t counter;
	uint64_t workload;
	uint32_t aux;
	uint32_t finished;
};

#if defined(_WIN64) && !defined(__CYGWIN__)
#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop))
PACK(struct publickey
{
	uint8_t parity;
	union {
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
});
#else
struct __attribute__((__packed__)) publickey {
  uint8_t parity;
	union	{
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
};
#endif

const char *Ccoinbuffer_default = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

char *Ccoinbuffer = (char*) Ccoinbuffer_default;
char *str_baseminikey = NULL;
char *raw_baseminikey = NULL;
char *minikeyN = NULL;
int minikey_n_limit;
	
const char *version = "0.2.230519 Satoshi Quest (legacy)";

#define CPU_GRP_SIZE 1024
//reserve
std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;

void menu();
void init_generator();

int searchbinary(struct address_value *buffer,char *data,int64_t array_length);
void sleep_ms(int milliseconds);
void writekey(bool compressed,Int *key);
void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);

bool readFileAddress(char *fileName);
bool forceReadFileAddress(char *fileName);

bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom);

void *thread_process(void *vargp);

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *bsgs_modes[5] = {"sequential","backward","both","random","dance"};
const char *modes[7] = {"xpoint","address","bsgs","rmd160","pub2rmd","minikeys","vanity"};
const char *cryptos[3] = {"btc","eth","all"};
const char *publicsearch[3] = {"uncompress","compress","both"};
const char *default_fileName = "addresses.txt";

#if defined(_WIN64) && !defined(__CYGWIN__)
HANDLE* tid = NULL;
HANDLE write_keys;
HANDLE write_random;
HANDLE bsgs_thread;
HANDLE *bPload_mutex;
#else
pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t bsgs_thread;
pthread_mutex_t *bPload_mutex;
#endif

uint64_t FINISHED_THREADS_COUNTER = 0;
uint64_t FINISHED_THREADS_BP = 0;
uint64_t THREADCYCLES = 0;
uint64_t THREADCOUNTER = 0;
uint64_t FINISHED_ITEMS = 0;
uint64_t OLDFINISHED_ITEMS = -1;

uint8_t byte_encode_crypto = 0x00;		/* Bitcoin  */


int vanity_rmd_targets = 0;
int vanity_rmd_total = 0;
int *vanity_rmd_limits = NULL;
uint8_t ***vanity_rmd_limit_values_A = NULL,***vanity_rmd_limit_values_B = NULL;
int vanity_rmd_minimun_bytes_check_length = 999999;
char **vanity_address_targets = NULL;
struct bloom *vanity_bloom = NULL;

struct bloom bloom;

uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;

uint64_t N_SEQUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400;
uint64_t u64range;

Int OUTPUTSECONDS;

int FLAGSKIPCHECKSUM = 0;
int FLAGENDOMORPHISM = 0;

int FLAGBLOOMMULTIPLIER = 1;
int FLAGVANITY = 0;
int FLAGBASEMINIKEY = 0;
int FLAGBSGSMODE = 0;
int FLAGDEBUG = 0;
int FLAGQUIET = 0;
int FLAGMATRIX = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;

int FLAGSAVEREADFILE = 0;
int FLAGREADEDFILE1 = 0;
int FLAGREADEDFILE2 = 0;
int FLAGREADEDFILE3 = 0;
int FLAGREADEDFILE4 = 0;
int FLAGUPDATEFILE1 = 0;


int FLAGSTRIDE = 0;
int FLAGSEARCH = 2;
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAGMODE = MODE_ADDRESS;
int FLAGCRYPTO = 0;
int FLAGRAWDATA	= 0;
int FLAGRANDOM = 0;
int FLAG_N = 0;
int FLAGPRECALCUTED_P_FILE = 0;

int bitrange;
char *str_N;
char *range_start;
char *range_end;
char *str_stride;
Int stride;

uint64_t BSGS_XVALUE_RAM = 6;
uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;

/*
BSGS Variables
*/
int *bsgs_found;
std::vector<Point> OriginalPointsBSGS;
bool *OriginalPointsBSGScompressed;

uint64_t bytes;
char checksum[32],checksum_backup[32];
char buffer_bloom_file[1024];
struct bsgs_xvalue *bPtable;
struct address_value *addressTable;

struct oldbloom oldbloom_bP;

struct bloom *bloom_bP;
struct bloom *bloom_bPx2nd; //2nd Bloom filter check
struct bloom *bloom_bPx3rd; //3rd Bloom filter check

struct checksumsha256 *bloom_bP_checksums;
struct checksumsha256 *bloom_bPx2nd_checksums;
struct checksumsha256 *bloom_bPx3rd_checksums;

#if defined(_WIN64) && !defined(__CYGWIN__)
std::vector<HANDLE> bloom_bP_mutex;
std::vector<HANDLE> bloom_bPx2nd_mutex;
std::vector<HANDLE> bloom_bPx3rd_mutex;
#else
pthread_mutex_t *bloom_bP_mutex;
pthread_mutex_t *bloom_bPx2nd_mutex;
pthread_mutex_t *bloom_bPx3rd_mutex;
#endif




uint64_t bloom_bP_totalbytes = 0;
uint64_t bloom_bP2_totalbytes = 0;
uint64_t bloom_bP3_totalbytes = 0;
uint64_t bsgs_m = 4194304;
uint64_t bsgs_m2;
uint64_t bsgs_m3;
unsigned long int bsgs_aux;
uint32_t bsgs_point_number;

const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];




Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX;
Int BSGS_N;
Int BSGS_N_double;
Int BSGS_M;					//M is squareroot(N)
Int BSGS_M_double;
Int BSGS_M2;				//M2 is M/32
Int BSGS_M2_double;			//M2_double is M2 * 2
Int BSGS_M3;				//M3 is M2/32
Int BSGS_M3_double;			//M3_double is M3 * 2

Int ONE;
Int ZERO;
Int MPZAUX;

Point BSGS_P;			//Original P is actually G, but this P value change over time for calculations
Point BSGS_MP;			//MP values this is m * P
Point BSGS_MP2;			//MP2 values this is m2 * P
Point BSGS_MP3;			//MP3 values this is m3 * P

Point BSGS_MP_double;			//MP2 values this is m2 * P * 2
Point BSGS_MP2_double;			//MP2 values this is m2 * P * 2
Point BSGS_MP3_double;			//MP3 values this is m3 * P * 2



std::vector<Point> BSGS_AMP2;
std::vector<Point> BSGS_AMP3;

Point point_temp,point_temp2;	//Temp value for some process

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;

Int lambda,lambda2,beta,beta2;

Secp256K1 *secp;

int main(int argc, char **argv)	{
	char buffer[2048];
	char rawvalue[32];
	struct tothread *tt;	//tothread
	Tokenizer t,tokenizerbsgs;	//tokenizer
	char *fileName = NULL;
	char *hextemp = NULL;
	char *aux = NULL;
	char *aux2 = NULL;
	char *pointx_str = NULL;
	char *pointy_str = NULL;
	char *str_seconds = NULL;
	char *str_total = NULL;
	char *str_pretotal = NULL;
	char *str_divpretotal = NULL;
	char *bf_ptr = NULL;
	char *bPload_threads_available;
	FILE *fd,*fd_aux1,*fd_aux2,*fd_aux3;
	uint64_t BASE,PERTHREAD_R,itemsbloom,itemsbloom2,itemsbloom3;
	uint32_t finished;
	int i,readed,continue_flag,check_flag,c,salir,index_value;
	Int total,pretotal,debugcount_mpz,seconds,div_pretotal,int_aux,int_r,int_q,int58;
	struct bPload *bPload_temp_ptr;
	size_t rsize;

	pthread_mutex_init(&write_keys,NULL);
	pthread_mutex_init(&write_random,NULL);
	pthread_mutex_init(&bsgs_thread,NULL);
	int s;

	srand(time(NULL));
	secp = new Secp256K1();
	secp->Init();
	OUTPUTSECONDS.SetInt32(5);
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);
	int_randominit();
	
	printf("[+] Version %s, developed by AlbertoBSD\n",version);

	while ((c = getopt(argc, argv, "deh6MqRSB:b:H:c:C:E:f:I:k:l:m:N:n:p:r:s:t:v:G:8:z:")) != -1) {
		switch(c) {
			case '6':
				FLAGSKIPCHECKSUM = 1;
				fprintf(stderr,"[W] Skipping checksums on files\n");
			break;
			case 'B':
				index_value = indexOf(optarg,bsgs_modes,5);
				if(index_value >= 0 && index_value <= 4)	{
					FLAGBSGSMODE = index_value;
					//printf("[+] BSGS mode %s\n",optarg);
				}
				else	{
					fprintf(stderr,"[W] Ignoring unknow bsgs mode %s\n",optarg);
				}
			break;
			case 'b':
				bitrange = strtol(optarg,NULL,10);
				if(bitrange > 0 && bitrange <=256 )	{
					MPZAUX.Set(&ONE);
					MPZAUX.ShiftL(bitrange-1);
					bit_range_str_min = MPZAUX.GetBase16();
					checkpointer((void *)bit_range_str_min,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
					MPZAUX.Set(&ONE);
					MPZAUX.ShiftL(bitrange);
					if(MPZAUX.IsGreater(&secp->order))	{
						MPZAUX.Set(&secp->order);
					}
					bit_range_str_max = MPZAUX.GetBase16();
					checkpointer((void *)bit_range_str_max,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
					FLAGBITRANGE = 1;
				}
				else	{
					fprintf(stderr,"[E] invalid bits param: %s.\n",optarg);
				}
			break;
			case 'H':
			  // Set nilai bit_range_str_min dari argumen -x
				bit_range_str_min = optarg; 
      break;
			case 'c':
				index_value = indexOf(optarg,cryptos,3);
				switch(index_value) {
					case 0: //btc
						FLAGCRYPTO = CRYPTO_BTC;
					break;
					case 1: //eth
						FLAGCRYPTO = CRYPTO_ETH;
						printf("[+] Setting search for ETH adddress.\n");
					break;
					/*
					case 2: //all
						FLAGCRYPTO = CRYPTO_ALL;
					break;
					*/
					default:
						FLAGCRYPTO = CRYPTO_NONE;
						fprintf(stderr,"[E] Unknow crypto value %s\n",optarg);
						exit(EXIT_FAILURE);
					break;
				}
			break;
			case 'C':
				if(strlen(optarg) == 22)	{
					FLAGBASEMINIKEY = 1;
					str_baseminikey = (char*) malloc(23);
					checkpointer((void *)str_baseminikey,__FILE__,"malloc","str_baseminikey" ,__LINE__ - 1);
					raw_baseminikey = (char*) malloc(23);
					checkpointer((void *)raw_baseminikey,__FILE__,"malloc","raw_baseminikey" ,__LINE__ - 1);
					strncpy(str_baseminikey,optarg,22);
					for(i = 0; i< 21; i++)	{
						if(strchr(Ccoinbuffer,str_baseminikey[i+1]) != NULL)	{
							raw_baseminikey[i] = (int)(strchr(Ccoinbuffer,str_baseminikey[i+1]) - Ccoinbuffer) % 58;
						}
						else	{
							fprintf(stderr,"[E] invalid character in minikey\n");
							exit(EXIT_FAILURE);
						}
						
					}
				}
				else	{
					fprintf(stderr,"[E] Invalid Minikey length %li : %s\n",strlen(optarg),optarg);
					exit(EXIT_FAILURE);
				}
				
			break;
			case 'd':
				FLAGDEBUG = 1;
				printf("[+] Flag DEBUG enabled\n");
			break;
			case 'e':
				FLAGENDOMORPHISM = 1;
				printf("[+] Endomorphism enabled\n");
				lambda.SetBase16("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");
				lambda2.SetBase16("ac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283ce");
				beta.SetBase16("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");
				beta2.SetBase16("851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40");
			break;
			case 'f':
				FLAGFILE = 1;
				fileName = optarg;
			break;
			case 'I':
				FLAGSTRIDE = 1;
				str_stride = optarg;
			break;
			case 'k':
				KFACTOR = (int)strtol(optarg,NULL,10);
				if(KFACTOR <= 0)	{
					KFACTOR = 1;
				}
				printf("[+] K factor %i\n",KFACTOR);
			break;

			case 'l':
				switch(indexOf(optarg,publicsearch,3)) {
					case SEARCH_UNCOMPRESS:
						FLAGSEARCH = SEARCH_UNCOMPRESS;
						printf("[+] Search uncompress only\n");
					break;
					case SEARCH_COMPRESS:
						FLAGSEARCH = SEARCH_COMPRESS;
						printf("[+] Search compress only\n");
					break;
					case SEARCH_BOTH:
						FLAGSEARCH = SEARCH_BOTH;
						printf("[+] Search both compress and uncompress\n");
					break;
				}
			break;
			case 'M':
				FLAGMATRIX = 1;
				printf("[+] Matrix screen\n");
			break;
			case 'm':
				switch(indexOf(optarg,modes,7)) {
					case MODE_XPOINT: //xpoint
						FLAGMODE = MODE_XPOINT;
						printf("[+] Mode xpoint\n");
					break;
					case MODE_ADDRESS: //address
						FLAGMODE = MODE_ADDRESS;
						printf("[+] Mode address\n");
					break;
					case MODE_BSGS:
						FLAGMODE = MODE_BSGS;
						//printf("[+] Mode BSGS\n");
					break;
					case MODE_RMD160:
						FLAGMODE = MODE_RMD160;
						FLAGCRYPTO = CRYPTO_BTC;
						printf("[+] Mode rmd160\n");
					break;
					case MODE_PUB2RMD:
						FLAGMODE = MODE_PUB2RMD;
						printf("[+] Mode pub2rmd\n");
					break;
					case MODE_MINIKEYS:
						FLAGMODE = MODE_MINIKEYS;
						printf("[+] Mode minikeys\n");
					break;
					case MODE_VANITY:
						FLAGMODE = MODE_VANITY;
						printf("[+] Mode vanity\n");
						if(vanity_bloom == NULL){
							vanity_bloom = (struct bloom*) calloc(1,sizeof(struct bloom));
							checkpointer((void *)vanity_bloom,__FILE__,"calloc","vanity_bloom" ,__LINE__ -1);
						}
					break;
					default:
						fprintf(stderr,"[E] Unknow mode value %s\n",optarg);
						exit(EXIT_FAILURE);
					break;
				}
			break;
			case 'n':
				FLAG_N = 1;
				str_N = optarg;
			break;
			case 'q':
				FLAGQUIET	= 1;
				printf("[+] Quiet thread output\n");
			break;
			case 'R':
				printf("[+] Random mode\n");
				FLAGRANDOM = 1;
				FLAGBSGSMODE =  3;
			break;
			case 'r':
				if(optarg != NULL)	{
					stringtokenizer(optarg,&t);
					switch(t.n)	{
						case 1:
							range_start = nextToken(&t);
							if(isValidHex(range_start)) {
								FLAGRANGE = 1;
								range_end = secp->order.GetBase16();
							}
							else	{
								fprintf(stderr,"[E] Invalid hexstring : %s.\n",range_start);
							}
						break;
						case 2:
							range_start = nextToken(&t);
							range_end	 = nextToken(&t);
							if(isValidHex(range_start) && isValidHex(range_end)) {
									FLAGRANGE = 1;
							}
							else	{
								if(isValidHex(range_start)) {
									fprintf(stderr,"[E] Invalid hexstring : %s\n",range_start);
								}
								else	{
									fprintf(stderr,"[E] Invalid hexstring : %s\n",range_end);
								}
							}
						break;
						default:
							printf("[E] Unknow number of Range Params: %i\n",t.n);
						break;
					}
				}
			break;
			case 's':
				OUTPUTSECONDS.SetBase10(optarg);
				if(OUTPUTSECONDS.IsLower(&ZERO))	{
					OUTPUTSECONDS.SetInt32(5);
				}
				if(OUTPUTSECONDS.IsZero())	{
					printf("[+] Turn off stats output\n");
				}
				else	{
					hextemp = OUTPUTSECONDS.GetBase10();
					printf("[+] Stats output every %s seconds\n",hextemp);
					free(hextemp);
				}
			break;
			case 'S':
				FLAGSAVEREADFILE = 1;
			break;
			case 't':
				NTHREADS = strtol(optarg,NULL,10);
				if(NTHREADS <= 0)	{
					NTHREADS = 1;
				}
				printf((NTHREADS > 1) ? "[+] Threads : %u\n": "[+] Thread : %u\n",NTHREADS);
			break;
			case '8':
				if(strlen(optarg) == 58)	{
					Ccoinbuffer = optarg; 
					printf("[+] Base58 for Minikeys %s\n",Ccoinbuffer);
				}
				else	{
					fprintf(stderr,"[E] The base58 alphabet must be 58 characters long.\n");
					exit(EXIT_FAILURE);
				}
			break;
			case 'z':
				FLAGBLOOMMULTIPLIER= strtol(optarg,NULL,10);
				if(FLAGBLOOMMULTIPLIER <= 0)	{
					FLAGBLOOMMULTIPLIER = 1;
				}
				printf("[+] Bloom Size Multiplier %i\n",FLAGBLOOMMULTIPLIER);
			break;
			default:
				fprintf(stderr,"[E] Unknow opcion -%c\n",c);
				exit(EXIT_FAILURE);
			break;
		}
	}

	if(  FLAGBSGSMODE == MODE_BSGS && FLAGENDOMORPHISM)	{
		fprintf(stderr,"[E] Endomorphism doesn't work with BSGS\n");
		exit(EXIT_FAILURE);
	}
	if( ( FLAGBSGSMODE == MODE_BSGS || FLAGBSGSMODE == MODE_PUB2RMD ) && FLAGSTRIDE)	{
		fprintf(stderr,"[E] Stride doesn't work with BSGS, pub2rmd\n");
		exit(EXIT_FAILURE);
	}
	if(FLAGSTRIDE)	{
		if(str_stride[0] == '0' && str_stride[1] == 'x')	{
			stride.SetBase16(str_stride+2);
		}
		else{
			stride.SetBase10(str_stride);
		}
		printf("[+] Stride : %s\n",stride.GetBase10());
	}
	else	{
		FLAGSTRIDE = 1;
		stride.Set(&ONE);
	}

	init_generator();
	if(FLAGMODE == MODE_BSGS )	{
		printf("[+] Mode BSGS %s\n",bsgs_modes[FLAGBSGSMODE]);
	}
	if(FLAGFILE == 0) {
		fileName =(char*) default_fileName;
	}
	if(FLAGMODE == MODE_ADDRESS && FLAGCRYPTO == CRYPTO_NONE) {	//When none crypto is defined the default search is for Bitcoin
		FLAGCRYPTO = CRYPTO_BTC;
		printf("[+] Setting search for btc adddress\n");
	}
	if(FLAGRANGE) {
		n_range_start.SetBase16(range_start);
		if(n_range_start.IsZero())	{
			n_range_start.AddOne();
		}
		n_range_end.SetBase16(range_end);
		if(n_range_start.IsEqual(&n_range_end) == false ) {
			if(  n_range_start.IsLower(&secp->order) &&  n_range_end.IsLowerOrEqual(&secp->order) )	{
				if( n_range_start.IsGreater(&n_range_end)) {
					fprintf(stderr,"[W] Opps, start range can't be great than end range. Swapping them\n");
					n_range_aux.Set(&n_range_start);
					n_range_start.Set(&n_range_end);
					n_range_end.Set(&n_range_aux);
				}
				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
			}
			else	{
				fprintf(stderr,"[E] Start and End range can't be great than N\nFallback to random mode!\n");
				FLAGRANGE = 0;
			}
		}
		else	{
			fprintf(stderr,"[E] Start and End range can't be the same\nFallback to random mode!\n");
			FLAGRANGE = 0;
		}
	}
	if(FLAGMODE != MODE_BSGS && FLAGMODE != MODE_MINIKEYS)	{
		BSGS_N.SetInt32(DEBUGCOUNT);
		if(FLAGRANGE == 0 && FLAGBITRANGE == 0)	{
			n_range_start.SetInt32(1);
			n_range_end.Set(&secp->order);
			n_range_diff.Set(&n_range_end);
			n_range_diff.Sub(&n_range_start);
		}
		else	{
			if(FLAGBITRANGE)	{
				n_range_start.SetBase16(bit_range_str_min);
				n_range_end.SetBase16(bit_range_str_max);
				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
			}
			else	{
				if(FLAGRANGE == 0)	{
					fprintf(stderr,"[W] WTF!\n");
				}
			}
		}
	}
	N = 0;
	if(FLAGMODE != MODE_BSGS )	{
		if(FLAG_N){
			if(str_N[0] == '0' && str_N[1] == 'x')	{
				N_SEQUENTIAL_MAX =strtol(str_N,NULL,16);
			}
			else	{
				N_SEQUENTIAL_MAX =strtol(str_N,NULL,10);
			}
			
			if(N_SEQUENTIAL_MAX < 1024)	{
				fprintf(stderr,"[I] n value need to be equal or great than 1024, back to defaults\n");
				FLAG_N = 0;
				N_SEQUENTIAL_MAX = 0x100000000;
			}
			if(N_SEQUENTIAL_MAX % 1024 != 0)	{
				fprintf(stderr,"[I] n value need to be multiplier of  1024\n");
				FLAG_N = 0;
				N_SEQUENTIAL_MAX = 0x100000000;
			}
		}
		printf("[+] N = %p\n",(void*)N_SEQUENTIAL_MAX);
		if(FLAGMODE == MODE_MINIKEYS)	{
			BSGS_N.SetInt32(DEBUGCOUNT);
			if(FLAGBASEMINIKEY)	{
				printf("[+] Base Minikey : %s\n",str_baseminikey);
			}
			minikeyN = (char*) malloc(22);
			checkpointer((void *)minikeyN,__FILE__,"malloc","minikeyN" ,__LINE__ -1);
			i =0;
			int58.SetInt32(58);
			int_aux.SetInt64(N_SEQUENTIAL_MAX);
			int_aux.Mult(253);	
			/* We get approximately one valid mini key for each 256 candidates mini keys since this is only statistics we multiply N_SEQUENTIAL_MAX by 253 to ensure not missed one one candidate minikey between threads... in this approach we repeat from 1 to 3 candidates in each N_SEQUENTIAL_MAX cycle IF YOU FOUND some other workaround please let me know */
			i = 20;
			salir = 0;
			do	{
				if(!int_aux.IsZero())	{
					int_r.Set(&int_aux);
					int_r.Mod(&int58);
					int_q.Set(&int_aux);
					minikeyN[i] = (uint8_t)int_r.GetInt64();
					int_q.Sub(&int_r);
					int_q.Div(&int58);
					int_aux.Set(&int_q);
					i--;
				}
				else	{
					salir =1;
				}
			}while(!salir && i > 0);
			minikey_n_limit = 21 -i;
		}
		else	{
			if(FLAGBITRANGE)	{	// Bit Range
				printf("[+] Bit Range %i\n",bitrange);
			}
			else	{
				printf("[+] Range \n");
			}
		}
		if(FLAGMODE != MODE_MINIKEYS)	{
			hextemp = n_range_start.GetBase16();
			printf("[+] -- from : 0x%s\n",hextemp);
			free(hextemp);
			hextemp = n_range_end.GetBase16();
			printf("[+] -- to   : 0x%s\n",hextemp);
			free(hextemp);
		}

		switch(FLAGMODE)	{
			case MODE_MINIKEYS:
			case MODE_PUB2RMD:
			case MODE_RMD160:
			case MODE_ADDRESS:
			case MODE_XPOINT:
				if(!readFileAddress(fileName))	{
					fprintf(stderr,"[E] Unenexpected error\n");
					exit(EXIT_FAILURE);
				}
			break;
		}
	}
	if(FLAGMODE == MODE_BSGS )	{
		printf("[+] Opening file %s\n",fileName);
		fd = fopen(fileName,"rb");
		if(fd == NULL)	{
			fprintf(stderr,"[E] Can't open file %s\n",fileName);
			exit(EXIT_FAILURE);
		}
		aux = (char*) malloc(1024);
		checkpointer((void *)aux,__FILE__,"malloc","aux" ,__LINE__ - 1);
		while(!feof(fd))	{
			if(fgets(aux,1022,fd) == aux)	{
				trim(aux," \t\n\r");
				if(strlen(aux) >= 128)	{	//Length of a full address in hexadecimal without 04
						N++;
				}else	{
					if(strlen(aux) >= 66)	{
						N++;
					}
				}
			}
		}
		if(N == 0)	{
			fprintf(stderr,"[E] There is no valid data in the file\n");
			exit(EXIT_FAILURE);
		}
		bsgs_found = (int*) calloc(N,sizeof(int));
		checkpointer((void *)bsgs_found,__FILE__,"calloc","bsgs_found" ,__LINE__ -1 );
		OriginalPointsBSGS.resize(N,secp->G);
		OriginalPointsBSGScompressed = (bool*) malloc(N*sizeof(bool));
		checkpointer((void *)OriginalPointsBSGScompressed,__FILE__,"malloc","OriginalPointsBSGScompressed" ,__LINE__ -1 );
		pointx_str = (char*) malloc(65);
		checkpointer((void *)pointx_str,__FILE__,"malloc","pointx_str" ,__LINE__ -1 );
		pointy_str = (char*) malloc(65);
		checkpointer((void *)pointy_str,__FILE__,"malloc","pointy_str" ,__LINE__ -1 );
		fseek(fd,0,SEEK_SET);
		i = 0;
		while(!feof(fd))	{
			if(fgets(aux,1022,fd) == aux)	{
				trim(aux," \t\n\r");
				if(strlen(aux) >= 66)	{
					stringtokenizer(aux,&tokenizerbsgs);
					aux2 = nextToken(&tokenizerbsgs);
					memset(pointx_str,0,65);
					memset(pointy_str,0,65);
					switch(strlen(aux2))	{
						case 66:	//Compress
							if(secp->ParsePublicKeyHex(aux2,OriginalPointsBSGS[i],OriginalPointsBSGScompressed[i]))	{
								i++;
							}
							else	{
								N--;
							}

						break;
						case 130:	//With the 04

							if(secp->ParsePublicKeyHex(aux2,OriginalPointsBSGS[i],OriginalPointsBSGScompressed[i]))	{
								i++;
							}
							else	{
								N--;
							}

						break;
						default:
							printf("Invalid length: %s\n",aux2);
							N--;
						break;
					}
					freetokenizer(&tokenizerbsgs);
				}
			}
		}
		fclose(fd);
		bsgs_point_number = N;
		if(bsgs_point_number > 0)	{
			printf("[+] Added %u points from file\n",bsgs_point_number);
		}
		else	{
			fprintf(stderr,"[E] The file don't have any valid publickeys\n");
			exit(EXIT_FAILURE);
		}
		BSGS_N.SetInt32(0);
		BSGS_M.SetInt32(0);
		

		BSGS_M.SetInt64(bsgs_m);


		if(FLAG_N)	{	//Custom N by the -n param
						
			/* Here we need to validate if the given string is a valid hexadecimal number or a base 10 number*/
			
			/* Now the conversion*/
			if(str_N[0] == '0' && str_N[1] == 'x' )	{	/*We expected a hexadecimal value after 0x  -> str_N +2 */
				BSGS_N.SetBase16((char*)(str_N+2));
			}
			else	{
				BSGS_N.SetBase10(str_N);
			}
			
		}
		else	{	//Default N
			BSGS_N.SetInt64((uint64_t)0x100000000000);
		}

		if(BSGS_N.HasSqrt())	{	//If the root is exact
			BSGS_M.Set(&BSGS_N);
			BSGS_M.ModSqrt();
		}
		else	{
			fprintf(stderr,"[E] -n param doesn't have exact square root\n");
			exit(EXIT_FAILURE);
		}

		BSGS_AUX.Set(&BSGS_M);
		BSGS_AUX.Mod(&BSGS_GROUP_SIZE);	
		
		if(!BSGS_AUX.IsZero()){ //If M is not divisible by  BSGS_GROUP_SIZE (1024) 
			hextemp = BSGS_GROUP_SIZE.GetBase10();
			fprintf(stderr,"[E] M value is not divisible by %s\n",hextemp);
			exit(EXIT_FAILURE);
		}

		bsgs_m = BSGS_M.GetInt64();

		if(FLAGRANGE || FLAGBITRANGE)	{
			if(FLAGBITRANGE)	{	// Bit Range
				n_range_start.SetBase16(bit_range_str_min);
				n_range_end.SetBase16(bit_range_str_max);

				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
				printf("[+] Bit Range %i\n",bitrange);
				printf("[+] -- from : 0x%s\n",bit_range_str_min);
				printf("[+] -- to   : 0x%s\n",bit_range_str_max);
			}
			else	{
				printf("[+] Range \n");
				printf("[+] -- from : 0x%s\n",range_start);
				printf("[+] -- to   : 0x%s\n",range_end);
			}
		}
		else	{	//Random start

			n_range_start.SetInt32(1);
			n_range_end.Set(&secp->order);
			n_range_diff.Rand(&n_range_start,&n_range_end);
			n_range_start.Set(&n_range_diff);
		}
		BSGS_CURRENT.Set(&n_range_start);


		if(n_range_diff.IsLower(&BSGS_N) )	{
			fprintf(stderr,"[E] the given range is small\n");
			exit(EXIT_FAILURE);
		}
		
		/*
	M	2199023255552
		109951162777.6
	M2	109951162778
		5497558138.9
	M3	5497558139
		*/

		BSGS_M.Mult((uint64_t)KFACTOR);
		BSGS_AUX.SetInt32(32);
		BSGS_R.Set(&BSGS_M);
		BSGS_R.Mod(&BSGS_AUX);
		BSGS_M2.Set(&BSGS_M);
		BSGS_M2.Div(&BSGS_AUX);

		if(!BSGS_R.IsZero())	{ /* If BSGS_M modulo 32 is not 0*/
			BSGS_M2.AddOne();
		}
		

		BSGS_M_double.SetInt32(2);
		BSGS_M_double.Mult(&BSGS_M);
		
		
		BSGS_M2_double.SetInt32(2);
		BSGS_M2_double.Mult(&BSGS_M2);

		BSGS_R.Set(&BSGS_M2);
		BSGS_R.Mod(&BSGS_AUX);
		
		BSGS_M3.Set(&BSGS_M2);
		BSGS_M3.Div(&BSGS_AUX);
		
		if(!BSGS_R.IsZero())	{ /* If BSGS_M2 modulo 32 is not 0*/
			BSGS_M3.AddOne();
		}
		
		BSGS_M3_double.SetInt32(2);
		BSGS_M3_double.Mult(&BSGS_M3);

		bsgs_m2 =  BSGS_M2.GetInt64();
		bsgs_m3 =  BSGS_M3.GetInt64();
		
		BSGS_AUX.Set(&BSGS_N);
		BSGS_AUX.Div(&BSGS_M);
		
		BSGS_R.Set(&BSGS_N);
		BSGS_R.Mod(&BSGS_M);

		if(!BSGS_R.IsZero())	{ /* if BSGS_N modulo BSGS_M is not 0*/
			BSGS_N.Set(&BSGS_M);
			BSGS_N.Mult(&BSGS_AUX);
		}

		bsgs_m = BSGS_M.GetInt64();
		bsgs_aux = BSGS_AUX.GetInt64();
		
		BSGS_N_double.SetInt32(2);
		BSGS_N_double.Mult(&BSGS_N);
		
		hextemp = BSGS_N.GetBase16();
		printf("[+] N = 0x%s\n",hextemp);
		free(hextemp);
		if(((uint64_t)(bsgs_m/256)) > 10000)	{
			itemsbloom = (uint64_t)(bsgs_m / 256);
			if(bsgs_m % 256 != 0 )	{
				itemsbloom++;
			}
		}
		else{
			itemsbloom = 1000;
		}
		
		if(((uint64_t)(bsgs_m2/256)) > 1000)	{
			itemsbloom2 = (uint64_t)(bsgs_m2 / 256);
			if(bsgs_m2 % 256 != 0)	{
				itemsbloom2++;
			}
		}
		else	{
			itemsbloom2 = 1000;
		}
		
		if(((uint64_t)(bsgs_m3/256)) > 1000)	{
			itemsbloom3 = (uint64_t)(bsgs_m3/256);
			if(bsgs_m3 % 256 != 0 )	{
				itemsbloom3++;
			}
		}
		else	{
			itemsbloom3 = 1000;
		}
		
		printf("[+] Bloom filter for %" PRIu64 " elements ",bsgs_m);
		bloom_bP = (struct bloom*)calloc(256,sizeof(struct bloom));
		checkpointer((void *)bloom_bP,__FILE__,"calloc","bloom_bP" ,__LINE__ -1 );
		bloom_bP_checksums = (struct checksumsha256*)calloc(256,sizeof(struct checksumsha256));
		checkpointer((void *)bloom_bP_checksums,__FILE__,"calloc","bloom_bP_checksums" ,__LINE__ -1 );
		
#if defined(_WIN64) && !defined(__CYGWIN__)
		bloom_bP_mutex = (HANDLE*) calloc(256,sizeof(HANDLE));
		
#else
		bloom_bP_mutex = (pthread_mutex_t*) calloc(256,sizeof(pthread_mutex_t));
#endif
		checkpointer((void *)bloom_bP_mutex,__FILE__,"calloc","bloom_bP_mutex" ,__LINE__ -1 );
		

		fflush(stdout);
		bloom_bP_totalbytes = 0;
		for(i=0; i< 256; i++)	{
#if defined(_WIN64) && !defined(__CYGWIN__)
			bloom_bP_mutex[i] = CreateMutex(NULL, FALSE, NULL);
#else
			pthread_mutex_init(&bloom_bP_mutex[i],NULL);
#endif
			if(bloom_init2(&bloom_bP[i],itemsbloom,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init _ [%i]\n",i);
				exit(EXIT_FAILURE);
			}
			bloom_bP_totalbytes += bloom_bP[i].bytes;
			//if(FLAGDEBUG) bloom_print(&bloom_bP[i]);
		}
		printf(": %.2f MB\n",(float)((float)(uint64_t)bloom_bP_totalbytes/(float)(uint64_t)1048576));


		printf("[+] Bloom filter for %" PRIu64 " elements ",bsgs_m2);
		
#if defined(_WIN64) && !defined(__CYGWIN__)
		bloom_bPx2nd_mutex = (HANDLE*) calloc(256,sizeof(HANDLE));
#else
		bloom_bPx2nd_mutex = (pthread_mutex_t*) calloc(256,sizeof(pthread_mutex_t));
#endif
		checkpointer((void *)bloom_bPx2nd_mutex,__FILE__,"calloc","bloom_bPx2nd_mutex" ,__LINE__ -1 );
		bloom_bPx2nd = (struct bloom*)calloc(256,sizeof(struct bloom));
		checkpointer((void *)bloom_bPx2nd,__FILE__,"calloc","bloom_bPx2nd" ,__LINE__ -1 );
		bloom_bPx2nd_checksums = (struct checksumsha256*) calloc(256,sizeof(struct checksumsha256));
		checkpointer((void *)bloom_bPx2nd_checksums,__FILE__,"calloc","bloom_bPx2nd_checksums" ,__LINE__ -1 );
		bloom_bP2_totalbytes = 0;
		for(i=0; i< 256; i++)	{
#if defined(_WIN64) && !defined(__CYGWIN__)
			bloom_bPx2nd_mutex[i] = CreateMutex(NULL, FALSE, NULL);
#else
			pthread_mutex_init(&bloom_bPx2nd_mutex[i],NULL);
#endif
			if(bloom_init2(&bloom_bPx2nd[i],itemsbloom2,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init _ [%i]\n",i);
				exit(EXIT_FAILURE);
			}
			bloom_bP2_totalbytes += bloom_bPx2nd[i].bytes;
			//if(FLAGDEBUG) bloom_print(&bloom_bPx2nd[i]);
		}
		printf(": %.2f MB\n",(float)((float)(uint64_t)bloom_bP2_totalbytes/(float)(uint64_t)1048576));
		

#if defined(_WIN64) && !defined(__CYGWIN__)
		bloom_bPx3rd_mutex = (HANDLE*) calloc(256,sizeof(HANDLE));
#else
		bloom_bPx3rd_mutex = (pthread_mutex_t*) calloc(256,sizeof(pthread_mutex_t));
#endif
		checkpointer((void *)bloom_bPx3rd_mutex,__FILE__,"calloc","bloom_bPx3rd_mutex" ,__LINE__ -1 );
		bloom_bPx3rd = (struct bloom*)calloc(256,sizeof(struct bloom));
		checkpointer((void *)bloom_bPx3rd,__FILE__,"calloc","bloom_bPx3rd" ,__LINE__ -1 );
		bloom_bPx3rd_checksums = (struct checksumsha256*) calloc(256,sizeof(struct checksumsha256));
		checkpointer((void *)bloom_bPx3rd_checksums,__FILE__,"calloc","bloom_bPx3rd_checksums" ,__LINE__ -1 );
		
		printf("[+] Bloom filter for %" PRIu64 " elements ",bsgs_m3);
		bloom_bP3_totalbytes = 0;
		for(i=0; i< 256; i++)	{
#if defined(_WIN64) && !defined(__CYGWIN__)
			bloom_bPx3rd_mutex[i] = CreateMutex(NULL, FALSE, NULL);
#else
			pthread_mutex_init(&bloom_bPx3rd_mutex[i],NULL);
#endif
			if(bloom_init2(&bloom_bPx3rd[i],itemsbloom3,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init [%i]\n",i);
				exit(EXIT_FAILURE);
			}
			bloom_bP3_totalbytes += bloom_bPx3rd[i].bytes;
			//if(FLAGDEBUG) bloom_print(&bloom_bPx3rd[i]);
		}
		printf(": %.2f MB\n",(float)((float)(uint64_t)bloom_bP3_totalbytes/(float)(uint64_t)1048576));
		//if(FLAGDEBUG) printf("[D] bloom_bP3_totalbytes : %" PRIu64 "\n",bloom_bP3_totalbytes);

		BSGS_MP = secp->ComputePublicKey(&BSGS_M);
		BSGS_MP_double = secp->ComputePublicKey(&BSGS_M_double);
		BSGS_MP2 = secp->ComputePublicKey(&BSGS_M2);
		BSGS_MP2_double = secp->ComputePublicKey(&BSGS_M2_double);
		BSGS_MP3 = secp->ComputePublicKey(&BSGS_M3);
		BSGS_MP3_double = secp->ComputePublicKey(&BSGS_M3_double);

		i= 0;

		/* New aMP table just to keep the same code of JLP */
		/* Auxiliar Points to speed up calculations for the main bloom filter check */
		Point bsP = secp->Negation(BSGS_MP_double);
		Point g = bsP;
		GSn.resize(CPU_GRP_SIZE/2,g);
		BSGS_AMP2.resize(32,g);
		BSGS_AMP3.resize(32,g);
		
		GSn[0] = g;

		g = secp->DoubleDirect(g);
		GSn[1] = g;
		
		for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
			g = secp->AddDirect(g,bsP);
			GSn[i] = g;
		}
		
		/* For next center point */
		_2GSn = secp->DoubleDirect(GSn[CPU_GRP_SIZE / 2 - 1]);

		i = 0;
		point_temp.Set(BSGS_MP2);
		BSGS_AMP2[0] = secp->Negation(point_temp);
		BSGS_AMP2[0].Reduce();
		point_temp.Set(BSGS_MP2_double);
		point_temp = secp->Negation(point_temp);
		point_temp.Reduce();
		
		for(i = 1; i < 32; i++)	{
			BSGS_AMP2[i] = secp->AddDirect(BSGS_AMP2[i-1],point_temp);
			BSGS_AMP2[i].Reduce();
		}
		
		i  = 0;
		point_temp.Set(BSGS_MP3);
		BSGS_AMP3[0] = secp->Negation(point_temp);
		BSGS_AMP3[0].Reduce();
		point_temp.Set(BSGS_MP3_double);
		point_temp = secp->Negation(point_temp);
		point_temp.Reduce();

		for(i = 1; i < 32; i++)	{
			BSGS_AMP3[i] = secp->AddDirect(BSGS_AMP3[i-1],point_temp);
			BSGS_AMP3[i].Reduce();
		}

		bytes = (uint64_t)bsgs_m3 * (uint64_t) sizeof(struct bsgs_xvalue);
		printf("[+] Allocating %.2f MB for %" PRIu64  " bP Points\n",(double)(bytes/1048576),bsgs_m3);
		
		bPtable = (struct bsgs_xvalue*) malloc(bytes);
		checkpointer((void *)bPtable,__FILE__,"malloc","bPtable" ,__LINE__ -1 );
		memset(bPtable,0,bytes);
		
		if(FLAGSAVEREADFILE)	{
			/*Reading file for 1st bloom filter */

			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_4_%" PRIu64 ".blm",bsgs_m);
			fd_aux1 = fopen(buffer_bloom_file,"rb");
			if(fd_aux1 != NULL)	{
				printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
				fflush(stdout);
				for(i = 0; i < 256;i++)	{
					bf_ptr = (char*) bloom_bP[i].bf;	/*We need to save the current bf pointer*/
					readed = fread(&bloom_bP[i],sizeof(struct bloom),1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					bloom_bP[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
					readed = fread(bloom_bP[i].bf,bloom_bP[i].bytes,1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					readed = fread(&bloom_bP_checksums[i],sizeof(struct checksumsha256),1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					if(FLAGSKIPCHECKSUM == 0)	{
						sha256((uint8_t*)bloom_bP[i].bf,bloom_bP[i].bytes,(uint8_t*)rawvalue);
						if(memcmp(bloom_bP_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bP_checksums[i].backup,rawvalue,32) != 0 )	{	/* Verification */
							fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
					}
					if(i % 64 == 0 )	{
						printf(".");
						fflush(stdout);
					}
				}
				printf(" Done!\n");
				fclose(fd_aux1);
				memset(buffer_bloom_file,0,1024);
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_3_%" PRIu64 ".blm",bsgs_m);
				fd_aux1 = fopen(buffer_bloom_file,"rb");
				if(fd_aux1 != NULL)	{
					printf("[W] Unused file detected %s you can delete it without worry\n",buffer_bloom_file);
					fclose(fd_aux1);
				}
				FLAGREADEDFILE1 = 1;
			}
			else	{	/*Checking for old file    keyhunt_bsgs_3_   */
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_3_%" PRIu64 ".blm",bsgs_m);
				fd_aux1 = fopen(buffer_bloom_file,"rb");
				if(fd_aux1 != NULL)	{
					printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						bf_ptr = (char*) bloom_bP[i].bf;	/*We need to save the current bf pointer*/
						readed = fread(&oldbloom_bP,sizeof(struct oldbloom),1,fd_aux1);
						
						/*
						if(FLAGDEBUG)	{
							printf("old Bloom filter %i\n",i);
							oldbloom_print(&oldbloom_bP);
						}
						*/
						
						if(readed != 1)	{
							fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						memcpy(&bloom_bP[i],&oldbloom_bP,sizeof(struct bloom));//We only need to copy the part data to the new bloom size, not from the old size
						bloom_bP[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
						
						readed = fread(bloom_bP[i].bf,bloom_bP[i].bytes,1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						memcpy(bloom_bP_checksums[i].data,oldbloom_bP.checksum,32);
						memcpy(bloom_bP_checksums[i].backup,oldbloom_bP.checksum_backup,32);
						memset(rawvalue,0,32);
						if(FLAGSKIPCHECKSUM == 0)	{
							sha256((uint8_t*)bloom_bP[i].bf,bloom_bP[i].bytes,(uint8_t*)rawvalue);
							if(memcmp(bloom_bP_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bP_checksums[i].backup,rawvalue,32) != 0 )	{	/* Verification */
								fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
								exit(EXIT_FAILURE);
							}
						}
						if(i % 32 == 0 )	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux1);
					FLAGUPDATEFILE1 = 1;	/* Flag to migrate the data to the new File keyhunt_bsgs_4_ */
					FLAGREADEDFILE1 = 1;
					
				}
				else	{
					FLAGREADEDFILE1 = 0;
					//Flag to make the new file
				}
			}
			
			/*Reading file for 2nd bloom filter */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_6_%" PRIu64 ".blm",bsgs_m2);
			fd_aux2 = fopen(buffer_bloom_file,"rb");
			if(fd_aux2 != NULL)	{
				printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
				fflush(stdout);
				for(i = 0; i < 256;i++)	{
					bf_ptr = (char*) bloom_bPx2nd[i].bf;	/*We need to save the current bf pointer*/
					readed = fread(&bloom_bPx2nd[i],sizeof(struct bloom),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					bloom_bPx2nd[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
					readed = fread(bloom_bPx2nd[i].bf,bloom_bPx2nd[i].bytes,1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					readed = fread(&bloom_bPx2nd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					memset(rawvalue,0,32);
					if(FLAGSKIPCHECKSUM == 0)	{								
						sha256((uint8_t*)bloom_bPx2nd[i].bf,bloom_bPx2nd[i].bytes,(uint8_t*)rawvalue);
						if(memcmp(bloom_bPx2nd_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bPx2nd_checksums[i].backup,rawvalue,32) != 0 )	{		/* Verification */
							fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
					}
					if(i % 64 == 0)	{
						printf(".");
						fflush(stdout);
					}
				}
				fclose(fd_aux2);
				printf(" Done!\n");
				memset(buffer_bloom_file,0,1024);
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_5_%" PRIu64 ".blm",bsgs_m2);
				fd_aux2 = fopen(buffer_bloom_file,"rb");
				if(fd_aux2 != NULL)	{
					printf("[W] Unused file detected %s you can delete it without worry\n",buffer_bloom_file);
					fclose(fd_aux2);
				}
				memset(buffer_bloom_file,0,1024);
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_1_%" PRIu64 ".blm",bsgs_m2);
				fd_aux2 = fopen(buffer_bloom_file,"rb");
				if(fd_aux2 != NULL)	{
					printf("[W] Unused file detected %s you can delete it without worry\n",buffer_bloom_file);
					fclose(fd_aux2);
				}
				FLAGREADEDFILE2 = 1;
			}
			else	{	
				FLAGREADEDFILE2 = 0;
			}
			
			/*Reading file for bPtable */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_2_%" PRIu64 ".tbl",bsgs_m3);
			fd_aux3 = fopen(buffer_bloom_file,"rb");
			if(fd_aux3 != NULL)	{
				printf("[+] Reading bP Table from file %s .",buffer_bloom_file);
				fflush(stdout);
				rsize = fread(bPtable,bytes,1,fd_aux3);
				if(rsize != 1)	{
					fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
				rsize = fread(checksum,32,1,fd_aux3);
				if(rsize != 1)	{
					fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
				if(FLAGSKIPCHECKSUM == 0)	{
					sha256((uint8_t*)bPtable,bytes,(uint8_t*)checksum_backup);
					if(memcmp(checksum,checksum_backup,32) != 0)	{
						fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
				}
				printf("... Done!\n");
				fclose(fd_aux3);
				FLAGREADEDFILE3 = 1;
			}
			else	{
				FLAGREADEDFILE3 = 0;
			}
			
			/*Reading file for 3rd bloom filter */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_7_%" PRIu64 ".blm",bsgs_m3);
			fd_aux2 = fopen(buffer_bloom_file,"rb");
			if(fd_aux2 != NULL)	{
				printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
				fflush(stdout);
				for(i = 0; i < 256;i++)	{
					bf_ptr = (char*) bloom_bPx3rd[i].bf;	/*We need to save the current bf pointer*/
					readed = fread(&bloom_bPx3rd[i],sizeof(struct bloom),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					bloom_bPx3rd[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
					readed = fread(bloom_bPx3rd[i].bf,bloom_bPx3rd[i].bytes,1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					readed = fread(&bloom_bPx3rd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					memset(rawvalue,0,32);
					if(FLAGSKIPCHECKSUM == 0)	{							
						sha256((uint8_t*)bloom_bPx3rd[i].bf,bloom_bPx3rd[i].bytes,(uint8_t*)rawvalue);
						if(memcmp(bloom_bPx3rd_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bPx3rd_checksums[i].backup,rawvalue,32) != 0 )	{		/* Verification */
							fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
					}
					if(i % 64 == 0)	{
						printf(".");
						fflush(stdout);
					}
				}
				fclose(fd_aux2);
				printf(" Done!\n");
				FLAGREADEDFILE4 = 1;
			}
			else	{
				FLAGREADEDFILE4 = 0;
			}
			
		}
		
		if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE3 || !FLAGREADEDFILE4)	{
			if(FLAGREADEDFILE1 == 1)	{
				/* 
					We need just to make File 2 to File 4 this is
					- Second bloom filter 5%
					- third  bloom fitler 0.25 %
					- bp Table 0.25 %
				*/
				printf("[I] We need to recalculate some files, don't worry this is only 3%% of the previous work\n");
				FINISHED_THREADS_COUNTER = 0;
				FINISHED_THREADS_BP = 0;
				FINISHED_ITEMS = 0;
				salir = 0;
				BASE = 0;
				THREADCOUNTER = 0;
				if(THREADBPWORKLOAD >= bsgs_m2)	{
					THREADBPWORKLOAD = bsgs_m2;
				}
				THREADCYCLES = bsgs_m2 / THREADBPWORKLOAD;
				PERTHREAD_R = bsgs_m2 % THREADBPWORKLOAD;
				if(PERTHREAD_R != 0)	{
					THREADCYCLES++;
				}
				
				printf("\r[+] processing %lu/%lu bP points : %i%%\r",FINISHED_ITEMS,bsgs_m,(int) (((double)FINISHED_ITEMS/(double)bsgs_m)*100));
				fflush(stdout);
				
#if defined(_WIN64) && !defined(__CYGWIN__)
				tid = (HANDLE*)calloc(NTHREADS, sizeof(HANDLE));
				checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );
				bPload_mutex = (HANDLE*) calloc(NTHREADS,sizeof(HANDLE));
#else
				tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
				bPload_mutex = (pthread_mutex_t*) calloc(NTHREADS,sizeof(pthread_mutex_t));
#endif
				checkpointer((void *)bPload_mutex,__FILE__,"calloc","bPload_mutex" ,__LINE__ -1 );
				bPload_temp_ptr = (struct bPload*) calloc(NTHREADS,sizeof(struct bPload));
				checkpointer((void *)bPload_temp_ptr,__FILE__,"calloc","bPload_temp_ptr" ,__LINE__ -1 );
				bPload_threads_available = (char*) calloc(NTHREADS,sizeof(char));
				checkpointer((void *)bPload_threads_available,__FILE__,"calloc","bPload_threads_available" ,__LINE__ -1 );
				
				memset(bPload_threads_available,1,NTHREADS);
				
				for(i = 0; i < NTHREADS; i++)	{
#if defined(_WIN64) && !defined(__CYGWIN__)
					bPload_mutex[i] = CreateMutex(NULL, FALSE, NULL);
#else
					pthread_mutex_init(&bPload_mutex[i],NULL);
#endif
				}
				
				do	{
					for(i = 0; i < NTHREADS && !salir; i++)	{

						if(bPload_threads_available[i] && !salir)	{
							bPload_threads_available[i] = 0;
							bPload_temp_ptr[i].from = BASE;
							bPload_temp_ptr[i].threadid = i;
							bPload_temp_ptr[i].finished = 0;
							if( THREADCOUNTER < THREADCYCLES-1)	{
								bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD;
								bPload_temp_ptr[i].workload = THREADBPWORKLOAD;
							}
							else	{
								bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
								bPload_temp_ptr[i].workload = THREADBPWORKLOAD + PERTHREAD_R;
								salir = 1;
								//if(FLAGDEBUG) printf("[D] Salir OK\n");
							}
							//if(FLAGDEBUG) printf("[I] %lu to %lu\n",bPload_temp_ptr[i].from,bPload_temp_ptr[i].to);
							pthread_detach(tid[i]);
							BASE+=THREADBPWORKLOAD;
							THREADCOUNTER++;
						}
					}

					if(OLDFINISHED_ITEMS != FINISHED_ITEMS)	{
						printf("\r[+] processing %lu/%lu bP points : %i%%\r",FINISHED_ITEMS,bsgs_m2,(int) (((double)FINISHED_ITEMS/(double)bsgs_m2)*100));
						fflush(stdout);
						OLDFINISHED_ITEMS = FINISHED_ITEMS;
					}
					
					for(i = 0 ; i < NTHREADS ; i++)	{

#if defined(_WIN64) && !defined(__CYGWIN__)
						WaitForSingleObject(bPload_mutex[i], INFINITE);
						finished = bPload_temp_ptr[i].finished;
						ReleaseMutex(bPload_mutex[i]);
#else
						pthread_mutex_lock(&bPload_mutex[i]);
						finished = bPload_temp_ptr[i].finished;
						pthread_mutex_unlock(&bPload_mutex[i]);
#endif
						if(finished)	{
							bPload_temp_ptr[i].finished = 0;
							bPload_threads_available[i] = 1;
							FINISHED_ITEMS += bPload_temp_ptr[i].workload;
							FINISHED_THREADS_COUNTER++;
						}
					}
					
				}while(FINISHED_THREADS_COUNTER < THREADCYCLES);
				printf("\r[+] processing %lu/%lu bP points : 100%%     \n",bsgs_m2,bsgs_m2);
				
				free(tid);
				free(bPload_mutex);
				free(bPload_temp_ptr);
				free(bPload_threads_available);
			}
			else{	
				/* We need just to do all the files 
					- first  bllom filter 100% 
					- Second bloom filter 5%
					- third  bloom fitler 0.25 %
					- bp Table 0.25 %
				*/
				FINISHED_THREADS_COUNTER = 0;
				FINISHED_THREADS_BP = 0;
				FINISHED_ITEMS = 0;
				salir = 0;
				BASE = 0;
				THREADCOUNTER = 0;
				if(THREADBPWORKLOAD >= bsgs_m)	{
					THREADBPWORKLOAD = bsgs_m;
				}
				THREADCYCLES = bsgs_m / THREADBPWORKLOAD;
				PERTHREAD_R = bsgs_m % THREADBPWORKLOAD;
				//if(FLAGDEBUG) printf("[D] THREADCYCLES: %lu\n",THREADCYCLES);
				if(PERTHREAD_R != 0)	{
					THREADCYCLES++;
					//if(FLAGDEBUG) printf("[D] PERTHREAD_R: %lu\n",PERTHREAD_R);
				}
				
				printf("\r[+] processing %lu/%lu bP points : %i%%\r",FINISHED_ITEMS,bsgs_m,(int) (((double)FINISHED_ITEMS/(double)bsgs_m)*100));
				fflush(stdout);
				
#if defined(_WIN64) && !defined(__CYGWIN__)
				tid = (HANDLE*)calloc(NTHREADS, sizeof(HANDLE));
				bPload_mutex = (HANDLE*) calloc(NTHREADS,sizeof(HANDLE));
#else
				tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
				bPload_mutex = (pthread_mutex_t*) calloc(NTHREADS,sizeof(pthread_mutex_t));
#endif
				checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );
				checkpointer((void *)bPload_mutex,__FILE__,"calloc","bPload_mutex" ,__LINE__ -1 );
				
				bPload_temp_ptr = (struct bPload*) calloc(NTHREADS,sizeof(struct bPload));
				checkpointer((void *)bPload_temp_ptr,__FILE__,"calloc","bPload_temp_ptr" ,__LINE__ -1 );
				bPload_threads_available = (char*) calloc(NTHREADS,sizeof(char));
				checkpointer((void *)bPload_threads_available,__FILE__,"calloc","bPload_threads_available" ,__LINE__ -1 );
				

				memset(bPload_threads_available,1,NTHREADS);
				
				for(i = 0; i < NTHREADS; i++)	{
#if defined(_WIN64) && !defined(__CYGWIN__)
					bPload_mutex = CreateMutex(NULL, FALSE, NULL);
#else
					pthread_mutex_init(&bPload_mutex[i],NULL);
#endif
				}
				
				do	{
					for(i = 0; i < NTHREADS && !salir; i++)	{

						if(bPload_threads_available[i] && !salir)	{
							bPload_threads_available[i] = 0;
							bPload_temp_ptr[i].from = BASE;
							bPload_temp_ptr[i].threadid = i;
							bPload_temp_ptr[i].finished = 0;
							if( THREADCOUNTER < THREADCYCLES-1)	{
								bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD;
								bPload_temp_ptr[i].workload = THREADBPWORKLOAD;
							}
							else	{
								bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
								bPload_temp_ptr[i].workload = THREADBPWORKLOAD + PERTHREAD_R;
								salir = 1;
								//if(FLAGDEBUG) printf("[D] Salir OK\n");
							}
							//if(FLAGDEBUG) printf("[I] %lu to %lu\n",bPload_temp_ptr[i].from,bPload_temp_ptr[i].to);
							pthread_detach(tid[i]);
							BASE+=THREADBPWORKLOAD;
							THREADCOUNTER++;
						}
					}
					if(OLDFINISHED_ITEMS != FINISHED_ITEMS)	{
						printf("\r[+] processing %lu/%lu bP points : %i%%\r",FINISHED_ITEMS,bsgs_m,(int) (((double)FINISHED_ITEMS/(double)bsgs_m)*100));
						fflush(stdout);
						OLDFINISHED_ITEMS = FINISHED_ITEMS;
					}
					
					for(i = 0 ; i < NTHREADS ; i++)	{

#if defined(_WIN64) && !defined(__CYGWIN__)
						WaitForSingleObject(bPload_mutex[i], INFINITE);
						finished = bPload_temp_ptr[i].finished;
						ReleaseMutex(bPload_mutex[i]);
#else
						pthread_mutex_lock(&bPload_mutex[i]);
						finished = bPload_temp_ptr[i].finished;
						pthread_mutex_unlock(&bPload_mutex[i]);
#endif
						if(finished)	{
							bPload_temp_ptr[i].finished = 0;
							bPload_threads_available[i] = 1;
							FINISHED_ITEMS += bPload_temp_ptr[i].workload;
							FINISHED_THREADS_COUNTER++;
						}
					}
					
				}while(FINISHED_THREADS_COUNTER < THREADCYCLES);
				printf("\r[+] processing %lu/%lu bP points : 100%%     \n",bsgs_m,bsgs_m);
				
				free(tid);
				free(bPload_mutex);
				free(bPload_temp_ptr);
				free(bPload_threads_available);
			}
		}
		
		if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE4)	{
			printf("[+] Making checkums .. ");
			fflush(stdout);
		}	
		if(!FLAGREADEDFILE1)	{
			for(i = 0; i < 256 ; i++)	{
				sha256((uint8_t*)bloom_bP[i].bf, bloom_bP[i].bytes,(uint8_t*) bloom_bP_checksums[i].data);
				memcpy(bloom_bP_checksums[i].backup,bloom_bP_checksums[i].data,32);
			}
			printf(".");
		}
		if(!FLAGREADEDFILE2)	{
			for(i = 0; i < 256 ; i++)	{
				sha256((uint8_t*)bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes,(uint8_t*) bloom_bPx2nd_checksums[i].data);
				memcpy(bloom_bPx2nd_checksums[i].backup,bloom_bPx2nd_checksums[i].data,32);
			}
			printf(".");
		}
		if(!FLAGREADEDFILE4)	{
			for(i = 0; i < 256 ; i++)	{
				sha256((uint8_t*)bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes,(uint8_t*) bloom_bPx3rd_checksums[i].data);
				memcpy(bloom_bPx3rd_checksums[i].backup,bloom_bPx3rd_checksums[i].data,32);
			}
			printf(".");
		}
		if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE4)	{
			printf(" done\n");
			fflush(stdout);
		}	
		if(FLAGSAVEREADFILE || FLAGUPDATEFILE1 )	{
			if(!FLAGREADEDFILE1 || FLAGUPDATEFILE1)	{
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_4_%" PRIu64 ".blm",bsgs_m);
				
				if(FLAGUPDATEFILE1)	{
					printf("[W] Updating old file into a new one\n");
				}
				
				/* Writing file for 1st bloom filter */
				
				fd_aux1 = fopen(buffer_bloom_file,"wb");
				if(fd_aux1 != NULL)	{
					printf("[+] Writing bloom filter to file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						readed = fwrite(&bloom_bP[i],sizeof(struct bloom),1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(bloom_bP[i].bf,bloom_bP[i].bytes,1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(&bloom_bP_checksums[i],sizeof(struct checksumsha256),1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						if(i % 64 == 0)	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux1);
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
			}
			if(!FLAGREADEDFILE2  )	{
				
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_6_%" PRIu64 ".blm",bsgs_m2);
								
				/* Writing file for 2nd bloom filter */
				fd_aux2 = fopen(buffer_bloom_file,"wb");
				if(fd_aux2 != NULL)	{
					printf("[+] Writing bloom filter to file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						readed = fwrite(&bloom_bPx2nd[i],sizeof(struct bloom),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(bloom_bPx2nd[i].bf,bloom_bPx2nd[i].bytes,1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(&bloom_bPx2nd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						if(i % 64 == 0)	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux2);	
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
			}
			
			if(!FLAGREADEDFILE3)	{
				/* Writing file for bPtable */
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_2_%" PRIu64 ".tbl",bsgs_m3);
				fd_aux3 = fopen(buffer_bloom_file,"wb");
				if(fd_aux3 != NULL)	{
					printf("[+] Writing bP Table to file %s .. ",buffer_bloom_file);
					fflush(stdout);
					readed = fwrite(bPtable,bytes,1,fd_aux3);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					readed = fwrite(checksum,32,1,fd_aux3);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
						exit(EXIT_FAILURE);
					}
					printf("Done!\n");
					fclose(fd_aux3);	
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
			}
			if(!FLAGREADEDFILE4)	{
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_7_%" PRIu64 ".blm",bsgs_m3);
								
				/* Writing file for 3rd bloom filter */
				fd_aux2 = fopen(buffer_bloom_file,"wb");
				if(fd_aux2 != NULL)	{
					printf("[+] Writing bloom filter to file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						readed = fwrite(&bloom_bPx3rd[i],sizeof(struct bloom),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(bloom_bPx3rd[i].bf,bloom_bPx3rd[i].bytes,1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						readed = fwrite(&bloom_bPx3rd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(EXIT_FAILURE);
						}
						if(i % 64 == 0)	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux2);
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(EXIT_FAILURE);
				}
			}
		}


		i = 0;

		steps = (uint64_t *) calloc(NTHREADS,sizeof(uint64_t));
		checkpointer((void *)steps,__FILE__,"calloc","steps" ,__LINE__ -1 );
		ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
		checkpointer((void *)ends,__FILE__,"calloc","ends" ,__LINE__ -1 );
		tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
		checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );
		
		for(i= 0;i < NTHREADS; i++)	{
			tt = (tothread*) malloc(sizeof(struct tothread));
			checkpointer((void *)tt,__FILE__,"malloc","tt" ,__LINE__ -1 );
			tt->nt = i;
			s = 0;
			if(s != 0)	{
				fprintf(stderr,"[E] thread thread_process\n");
				exit(EXIT_FAILURE);
			}
		}

		
		free(aux);
	}
	if(FLAGMODE != MODE_BSGS)	{
	
		steps = (uint64_t *) calloc(NTHREADS,sizeof(uint64_t));
		checkpointer((void *)steps,__FILE__,"calloc","steps" ,__LINE__ -1 );
		ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
		checkpointer((void *)ends,__FILE__,"calloc","ends" ,__LINE__ -1 );
		tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
		checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );
	
		for(i= 0;i < NTHREADS; i++)	{
			tt = (tothread*) malloc(sizeof(struct tothread));
			checkpointer((void *)tt,__FILE__,"malloc","tt" ,__LINE__ -1 );
			tt->nt = i;
			steps[i] = 0;
			s = 0;
			switch(FLAGMODE)	{
				case MODE_ADDRESS:
				case MODE_XPOINT:
				case MODE_RMD160:
					s = pthread_create(&tid[i],NULL,thread_process,(void *)tt);
				break;
			}
			if(s != 0)	{
				fprintf(stderr,"[E] pthread_create thread_process\n");
				exit(EXIT_FAILURE);
			}
		}
	}
	i = 0;
	
	while(i < 7)	{
		int_limits[i].SetBase10((char*)str_limits[i]);
		i++;
	}
	
	continue_flag = 1;
	total.SetInt32(0);
	pretotal.SetInt32(0);
	debugcount_mpz.Set(&BSGS_N);
	seconds.SetInt32(0);
	do	{
		sleep_ms(1000);
		seconds.AddOne();
		check_flag = 1;
		for(i = 0; i <NTHREADS && check_flag; i++) {
			check_flag &= ends[i];
		}
		if(check_flag)	{
			continue_flag = 0;
		}
		if(OUTPUTSECONDS.IsGreater(&ZERO) ){
			MPZAUX.Set(&seconds);
			MPZAUX.Mod(&OUTPUTSECONDS);
			if(MPZAUX.IsZero()) {
				total.SetInt32(0);
				i = 0;
				while(i < NTHREADS) {
					pretotal.Set(&debugcount_mpz);
					pretotal.Mult(steps[i]);					
					total.Add(&pretotal);
					i++;
				}
				
				if(FLAGENDOMORPHISM)	{
					if(FLAGMODE == MODE_XPOINT)	{
						total.Mult(3);
					}
					else	{
						total.Mult(6);
					}
				}
				else	{
					if(FLAGSEARCH == SEARCH_COMPRESS)	{
						total.Mult(2);
					}
				}
				

				pretotal.Set(&total);
				pretotal.Div(&seconds);
				str_seconds = seconds.GetBase10();
				str_pretotal = pretotal.GetBase10();
				str_total = total.GetBase10();
				
				if(pretotal.IsLower(&int_limits[0]))	{
					if(FLAGMATRIX)	{
						sprintf(buffer,"[+] Total %s keys in %s seconds: %s keys/s\n",str_total,str_seconds,str_pretotal);
					}
					else	{
						sprintf(buffer,"\r[+] Total %s keys in %s seconds: %s keys/s\r",str_total,str_seconds,str_pretotal);
					}
				}
				else	{
					i = 0;
					salir = 0;
					while( i < 6 && !salir)	{
						if(pretotal.IsLower(&int_limits[i+1]))	{
							salir = 1;
						}
						else	{
							i++;
						}
					}

					div_pretotal.Set(&pretotal);
					div_pretotal.Div(&int_limits[salir ? i : i-1]);
					str_divpretotal = div_pretotal.GetBase10();
					if(FLAGMATRIX)	{
						sprintf(buffer,"[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\n",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
					}
					else	{
						if(THREADOUTPUT == 1)	{
							sprintf(buffer,"\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\r",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
						}
						else	{
							sprintf(buffer,"\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\r",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
						}
					}
					free(str_divpretotal);

				}
				printf("%s",buffer);
				fflush(stdout);
				THREADOUTPUT = 0;			
				free(str_seconds);
				free(str_pretotal);
				free(str_total);
			}
		}
	}while(continue_flag);
	printf("\nEnd\n");
}

int searchbinary(struct address_value *buffer,char *data,int64_t array_length) {
	int64_t half,min,max,current;
	int r = 0,rcmp;
	min = 0;
	current = 0;
	max = array_length;
	half = array_length;
	while(!r && half >= 1) {
		half = (max - min)/2;
		rcmp = memcmp(data,buffer[current+half].value,20);
		if(rcmp == 0)	{
			r = 1;	//Found!!
		}
		else	{
			if(rcmp < 0) { //data < temp_read
				max = (max-half);
			}
			else	{ // data > temp_read
				min = (min+half);
			}
			current = min;
		}
	}
	return r;
}

void *thread_process(void *vargp)	{
	struct tothread *tt;
	Point pts[CPU_GRP_SIZE];
	Point endomorphism_beta[CPU_GRP_SIZE];
	Point endomorphism_beta2[CPU_GRP_SIZE];
	Point endomorphism_negeted_point[4];

	Int dx[CPU_GRP_SIZE / 2 + 1];
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Point pp;
	Point pn;
	int l,pp_offset,pn_offset;
	int i,hLength = (CPU_GRP_SIZE / 2 - 1);
	uint64_t j,count;
	Point R,temporal,publickey;
	int r,thread_number,continue_flag = 1,k;
	char *hextemp = NULL;
	
	char publickeyhashrmd160[20];
	char publickeyhashrmd160_uncompress[4][20];
	char rawvalue[32];
	
	char publickeyhashrmd160_endomorphism[12][4][20];
	
	bool calculate_y = FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH;
	Int key_mpz,keyfound,temp_stride;
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	grp->Set(dx);

	do {
		if(FLAGRANDOM){
			key_mpz.Rand(&n_range_start,&n_range_end);
		}
		else	{
			if(n_range_start.IsLower(&n_range_end))	{
				pthread_mutex_lock(&write_random);
				key_mpz.Set(&n_range_start);
				n_range_start.Add(N_SEQUENTIAL_MAX);
				pthread_mutex_unlock(&write_random);
			}
			else	{
				continue_flag = 0;
			}
		}
		if(continue_flag)	{
			count = 0;
			if(FLAGMATRIX)	{
					hextemp = key_mpz.GetBase16();
					printf("Base key: %s thread %i\n",hextemp,thread_number);
					fflush(stdout);
					free(hextemp);
			}
			else	{
				if(FLAGQUIET == 0){
					hextemp = key_mpz.GetBase16();
					printf("\rBase key: %s     \r",hextemp);
					fflush(stdout);
					free(hextemp);
					THREADOUTPUT = 1;
				}
			}
			do {
				temp_stride.SetInt32(CPU_GRP_SIZE / 2);
				temp_stride.Mult(&stride);
				key_mpz.Add(&temp_stride);
	 			startP = secp->ComputePublicKey(&key_mpz);
				key_mpz.Sub(&temp_stride);

				for(i = 0; i < hLength; i++) {
					dx[i].ModSub(&Gn[i].x,&startP.x);
				}
			
				dx[i].ModSub(&Gn[i].x,&startP.x);  // For the first point
				dx[i + 1].ModSub(&_2Gn.x,&startP.x); // For the next center point
				grp->ModInv();

				pts[CPU_GRP_SIZE / 2] = startP;

				for(i = 0; i<hLength; i++) {
					pp = startP;
					pn = startP;

					// P = startP + i*G
					dy.ModSub(&Gn[i].y,&pp.y);

					_s.ModMulK1(&dy,&dx[i]);        // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
					_p.ModSquareK1(&_s);            // _p = pow2(s)

					pp.x.ModNeg();
					pp.x.ModAdd(&_p);
					pp.x.ModSub(&Gn[i].x);           // rx = pow2(s) - p1.x - p2.x;

					if(calculate_y)	{
						pp.y.ModSub(&Gn[i].x,&pp.x);
						pp.y.ModMulK1(&_s);
						pp.y.ModSub(&Gn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);
					}

					// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
					dyn.Set(&Gn[i].y);
					dyn.ModNeg();
					dyn.ModSub(&pn.y);

					_s.ModMulK1(&dyn,&dx[i]);      // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
					_p.ModSquareK1(&_s);            // _p = pow2(s)
					pn.x.ModNeg();
					pn.x.ModAdd(&_p);
					pn.x.ModSub(&Gn[i].x);          // rx = pow2(s) - p1.x - p2.x;

					if(calculate_y)	{
						pn.y.ModSub(&Gn[i].x,&pn.x);
						pn.y.ModMulK1(&_s);
						pn.y.ModAdd(&Gn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);
					}

					pp_offset = CPU_GRP_SIZE / 2 + (i + 1);
					pn_offset = CPU_GRP_SIZE / 2 - (i + 1);

					pts[pp_offset] = pp;
					pts[pn_offset] = pn;
					
					if(FLAGENDOMORPHISM)	{
						/*
							Q = (x,y)
							For any point Q
							Q*lambda = (x*beta mod p ,y)
							Q*lambda is a Scalar Multiplication
							x*beta is just a Multiplication (Very fast)
						*/
						
						if( calculate_y  )	{
							endomorphism_beta[pp_offset].y.Set(&pp.y);
							endomorphism_beta[pn_offset].y.Set(&pn.y);
							endomorphism_beta2[pp_offset].y.Set(&pp.y);
							endomorphism_beta2[pn_offset].y.Set(&pn.y);
						}
						endomorphism_beta[pp_offset].x.ModMulK1(&pp.x, &beta);
						endomorphism_beta[pn_offset].x.ModMulK1(&pn.x, &beta);
						endomorphism_beta2[pp_offset].x.ModMulK1(&pp.x, &beta2);
						endomorphism_beta2[pn_offset].x.ModMulK1(&pn.x, &beta2);
					}
				}
				/*
					Half point for endomorphism because pts[CPU_GRP_SIZE / 2] was not calcualte in the previous cycle
				*/
				if(FLAGENDOMORPHISM)	{
					if( calculate_y  )	{

						endomorphism_beta[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
						endomorphism_beta2[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
					}
					endomorphism_beta[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &beta);
					endomorphism_beta2[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &beta2);
				}

				// First point (startP - (GRP_SZIE/2)*G)
				pn = startP;
				dyn.Set(&Gn[i].y);
				dyn.ModNeg();
				dyn.ModSub(&pn.y);

				_s.ModMulK1(&dyn,&dx[i]);
				_p.ModSquareK1(&_s);

				pn.x.ModNeg();
				pn.x.ModAdd(&_p);
				pn.x.ModSub(&Gn[i].x);
				
				if(calculate_y)	{
					pn.y.ModSub(&Gn[i].x,&pn.x);
					pn.y.ModMulK1(&_s);
					pn.y.ModAdd(&Gn[i].y);
				}

				pts[0] = pn;
				
				/*
					First point for endomorphism because pts[0] was not calcualte previously
				*/
				if(FLAGENDOMORPHISM)	{
					if( calculate_y  )	{
						endomorphism_beta[0].y.Set(&pn.y);
						endomorphism_beta2[0].y.Set(&pn.y);
					}
					endomorphism_beta[0].x.ModMulK1(&pn.x, &beta);
					endomorphism_beta2[0].x.ModMulK1(&pn.x, &beta2);
				}
				
				for(j = 0; j < CPU_GRP_SIZE/4;j++){
					switch(FLAGMODE)	{
						case MODE_RMD160:
										secp->GetHash160_fromX(P2PKH,0x02,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
										secp->GetHash160_fromX(P2PKH,0x03,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);
						break;
					}
					switch(FLAGMODE)	{
						case MODE_RMD160:
							for(k = 0; k < 4;k++)	{
							  if(FLAGENDOMORPHISM)	{
							    for(l = 0;l < 6; l++)	{
												r = bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k],MAXLENGTHADDRESS);
												if(r) {
													r = searchbinary(addressTable,publickeyhashrmd160_endomorphism[l][k],N);
													if(r) {
														keyfound.SetInt32(k);
														keyfound.Mult(&stride);
														keyfound.Add(&key_mpz);
														publickey = secp->ComputePublicKey(&keyfound);
														switch(l)	{
															case 0:	//Original point, prefix 02
																if(publickey.y.IsOdd())	{	//if the current publickey is odd that means, we need to negate the keyfound to get the correct key
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
																// else we dont need to chage the current keyfound because it already have prefix 02
															break;
															case 1:	//Original point, prefix 03
																if(publickey.y.IsEven())	{	//if the current publickey is even that means, we need to negate the keyfound to get the correct key
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
																// else we dont need to chage the current keyfound because it already have prefix 03
															break;
															case 2:	//Beta point, prefix 02
																keyfound.ModMulK1order(&lambda);
																if(publickey.y.IsOdd())	{	//if the current publickey is odd that means, we need to negate the keyfound to get the correct key
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
																// else we dont need to chage the current keyfound because it already have prefix 02
															break;
															case 3:	//Beta point, prefix 03											
																keyfound.ModMulK1order(&lambda);
																if(publickey.y.IsEven())	{	//if the current publickey is even that means, we need to negate the keyfound to get the correct key
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
																// else we dont need to chage the current keyfound because it already have prefix 02
															break;
															case 4:	//Beta^2 point, prefix 02
																keyfound.ModMulK1order(&lambda2);
																if(publickey.y.IsOdd())	{	//if the current publickey is odd that means, we need to negate the keyfound to get the correct key
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
																// else we dont need to chage the current keyfound because it already have prefix 02
															break;
															case 5:	//Beta^2 point, prefix 03
																keyfound.ModMulK1order(&lambda2);
																if(publickey.y.IsEven())	{	//if the current publickey is even that means, we need to negate the keyfound to get the correct key
																	keyfound.Neg();
																	keyfound.Add(&secp->order);
																}
																// else we dont need to chage the current keyfound because it already have prefix 02
															break;
														}
														writekey(true,&keyfound);
													}
												}
											}
							  }
							  else	{
							    for(l = 0;l < 2; l++)	{
							      r = bloom_check(&bloom,publickeyhashrmd160_endomorphism[l][k],MAXLENGTHADDRESS);
							      if(r) {
							        r = searchbinary(addressTable,publickeyhashrmd160_endomorphism[l][k],N);
							        if(r) {
							          keyfound.SetInt32(k);
							          keyfound.Mult(&stride);
							          keyfound.Add(&key_mpz);
							          publickey = secp->ComputePublicKey(&keyfound);
							          secp->GetHash160(P2PKH,true,publickey,(uint8_t*)publickeyhashrmd160);
							          if(memcmp(publickeyhashrmd160_endomorphism[l][k],publickeyhashrmd160,20) != 0)	{
							            keyfound.Neg();
							            keyfound.Add(&secp->order);
							          }
							          writekey(true,&keyfound);
							        }
							      }
							    }
							  }
							}
						break;
					}
					count+=4;
					temp_stride.SetInt32(4);
					temp_stride.Mult(&stride);
					key_mpz.Add(&temp_stride);
				}

				steps[thread_number]++;

				// Next start point (startP + GRP_SIZE*G)
				pp = startP;
				dy.ModSub(&_2Gn.y,&pp.y);

				_s.ModMulK1(&dy,&dx[i + 1]);
				_p.ModSquareK1(&_s);

				pp.x.ModNeg();
				pp.x.ModAdd(&_p);
				pp.x.ModSub(&_2Gn.x);

				//The Y value for the next start point always need to be calculated
				pp.y.ModSub(&_2Gn.x,&pp.x);
				pp.y.ModMulK1(&_s);
				pp.y.ModSub(&_2Gn.y);
				startP = pp;
			}while(count < N_SEQUENTIAL_MAX && continue_flag);
		}
	} while(continue_flag);
	ends[thread_number] = 1;
	return NULL;
}

void sleep_ms(int milliseconds)	{ // cross-platform sleep function
#if defined(_WIN64) && !defined(__CYGWIN__)
    Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    if (milliseconds >= 1000)
      sleep(milliseconds / 1000);
    usleep((milliseconds % 1000) * 1000);
#endif
}

void init_generator()	{
	Point G = secp->ComputePublicKey(&stride);
	Point g;
	Gn.resize(CPU_GRP_SIZE / 2,g);
	g.Set(G);
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g,G);
		Gn[i] = g;
	}
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
}

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line)	{
	if(ptr == NULL)	{
		fprintf(stderr,"[E] error in file %s, %s pointer %s on line %i\n",file,function,name,line); 
		exit(EXIT_FAILURE);
	}
}

void writekey(bool compressed,Int *key)	{
	Point publickey;
	FILE *keys;
	char *hextemp;
	hextemp = key->GetBase16();
	pthread_mutex_lock(&write_keys);
	keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
	if(keys != NULL)	{
		fprintf(keys,"Private Key:   %s\n",hextemp);
		fclose(keys);
	}
	printf("\nHit! Private Key:   %s\n",hextemp);
	pthread_mutex_unlock(&write_keys);
	free(hextemp);
}

bool readFileAddress(char *fileName)	{
	return forceReadFileAddress(fileName);
}

bool forceReadFileAddress(char *fileName)	{
	/* Here we read the original file as usual */
	FILE *fileDescriptor;
	bool validAddress;
	uint64_t numberItems,i;
	size_t r;
	uint8_t rawvalue[50];
	char aux[100],*hextemp;
	fileDescriptor = fopen(fileName,"r");	
	if(fileDescriptor == NULL)	{
		fprintf(stderr,"[E] Error opening the file %s, line %i\n",fileName,__LINE__ - 2);
		return false;
	}

	/*Count lines in the file*/
	numberItems = 0;
	while(!feof(fileDescriptor))	{
		hextemp = fgets(aux,100,fileDescriptor);
		trim(aux," \t\n\r");
		if(hextemp == aux)	{			
			r = strlen(aux);
			if(r > 20)	{ 
				numberItems++;
			}
		}
	}
	fseek(fileDescriptor,0,SEEK_SET);
	MAXLENGTHADDRESS = 20;		/*20 bytes beacuase we only need the data in binary*/
	
	printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n",numberItems,(double)(((double) sizeof(struct address_value)*numberItems)/(double)1048576));
	addressTable = (struct address_value*) malloc(sizeof(struct address_value)*numberItems);
	checkpointer((void *)addressTable,__FILE__,"malloc","addressTable" ,__LINE__ -1 );
		
	if(!initBloomFilter(&bloom,numberItems))
		return false;

	i = 0;
	while(i < numberItems)	{
		validAddress = false;
		memset(aux,0,100);
		memset(addressTable[i].value,0,sizeof(struct address_value));
		hextemp = fgets(aux,100,fileDescriptor);
		trim(aux," \t\n\r");			
		r = strlen(aux);
		if(r > 0 && r <= 40)	{
			if(r == 40 && isValidHex(aux))	{	//RMD
				hexs2bin(aux,rawvalue);				
				bloom_add(&bloom, rawvalue ,sizeof(struct address_value));
				memcpy(addressTable[i].value,rawvalue,sizeof(struct address_value));											
				i++;
				validAddress = true;
			}
		}
		if(!validAddress)	{
			fprintf(stderr,"[I] Ommiting invalid line %s\n",aux);
			numberItems--;
		}
	}
	N = numberItems;
	return true;
}

bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom)	{
	bool r = true;
	printf("[+] Bloom filter for %" PRIu64 " elements.\n",items_bloom);
	if(items_bloom <= 10000)	{
		if(bloom_init2(bloom_arg,10000,0.000001) == 1){
			fprintf(stderr,"[E] error bloom_init for 10000 elements.\n");
			r = false;
		}
	}
	else	{
		if(bloom_init2(bloom_arg,FLAGBLOOMMULTIPLIER*items_bloom,0.000001)	== 1){
			fprintf(stderr,"[E] error bloom_init for %" PRIu64 " elements.\n",items_bloom);
			r = false;
		}
	}
	printf("[+] Loading data to the bloomfilter total: %.2f MB\n",(double)(((double) bloom_arg->bytes)/(double)1048576));
	return r; 
}