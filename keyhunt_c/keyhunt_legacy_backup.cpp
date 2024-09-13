
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
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
#define MODE_ADDRESS 1
#define MODE_RMD160 3
struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
	char *rs;   //range start
	char *rpt;  //rng per thread
};

#define CPU_GRP_SIZE 1024
std::vector<Point> Gn;
Point _2Gn;
std::vector<Point> GSn;
Point _2GSn;
void init_generator();
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
const char *modes = {"rmd160"};

pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t bsgs_thread;

uint8_t byte_encode_crypto = 0x00;
struct bloom bloom;
uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;
uint64_t N_SEQUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400;
Int OUTPUTSECONDS;

// Membaca langsung 

int FLAGENDOMORPHISM = 0;
int FLAGBLOOMMULTIPLIER = 1;


int FLAGMATRIX = 0;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;

int FLAGSEARCH = 2;
int FLAGBITRANGE = 0;
int FLAGFILE = 0;
int FLAGMODE = MODE_ADDRESS;
int FLAG_N = 0;
int bitrange;
char *str_N;
char *range_start;
char *range_end;
char *str_stride;
Int stride;
uint64_t bytes;
struct address_value *addressTable;
struct oldbloom oldbloom_bP;
//const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits_prefixs[1] = {"Ekeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];
Int BSGS_N;
Int ONE;
Int ZERO;
Int MPZAUX;
Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int lambda,lambda2,beta,beta2;
Secp256K1 *secp;
int main(int argc, char **argv)	{
	char buffer[2048];
	struct tothread *tt;
	char *fileName = NULL;
	char *str_seconds = NULL;
	char *str_total = NULL;
	char *str_pretotal = NULL;
	char *str_divpretotal = NULL;
	int i,continue_flag,check_flag,c,salir;
	Int total,pretotal,debugcount_mpz,seconds,div_pretotal,int_aux,int_r,int_q,int58;
	pthread_mutex_init(&write_keys,NULL);
	pthread_mutex_init(&write_random,NULL);
	pthread_mutex_init(&bsgs_thread,NULL);
	int s;
	srand(time(NULL));
	secp = new Secp256K1();
	secp->Init();
	OUTPUTSECONDS.SetInt32(1);
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	
	while ((c = getopt(argc, argv, "deh6MqRSB:b:c:C:E:f:I:k:l:m:N:n:p:r:s:t:v:G:8:z:x:")) != -1) {
    switch(c) {
        case 'b':
            bitrange = strtol(optarg,NULL,10);
            if(bitrange > 0 && bitrange <=256 ) {
                MPZAUX.Set(&ONE);
                MPZAUX.ShiftL(bitrange-1);
                bit_range_str_min = MPZAUX.GetBase16();
                //bit_range_str_min = "1fa0000";
                checkpointer((void *)bit_range_str_min,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
                MPZAUX.Set(&ONE);
                MPZAUX.ShiftL(bitrange);
                if(MPZAUX.IsGreater(&secp->order)) {
                    MPZAUX.Set(&secp->order);
                }
                bit_range_str_max = MPZAUX.GetBase16();
                checkpointer((void *)bit_range_str_max,__FILE__,"malloc","bit_range_str_min" ,__LINE__ -1);
                FLAGBITRANGE = 1;
            }
            else {
                fprintf(stderr,"[E] invalid bits param: %s.\n",optarg);
            }
        break;
        break;
        case 'x':
            bit_range_str_min = optarg; // Set nilai bit_range_str_min dari argumen -x
            break;
        case 'f':
            FLAGFILE = 1;
            fileName = optarg;
        break;
        case 'm':
        case MODE_RMD160:
            FLAGMODE = MODE_RMD160;
            printf("[+] Mode rmd160\n");
        break;
    }
}

	stride.Set(&ONE);
	init_generator();
// Batas Range
	BSGS_N.SetInt32(DEBUGCOUNT);
	n_range_start.SetBase16(bit_range_str_min);
	n_range_end.SetBase16(bit_range_str_max);
	n_range_diff.Set(&n_range_end);
	n_range_diff.Sub(&n_range_start);
	printf("[+] Bit Range %i\n",bitrange);
	printf("[+] -- from : 0x%s\n",bit_range_str_min);
	printf("[+] -- to   : 0x%s\n",bit_range_str_max);
  
	if(FLAG_N){
    if(str_N[0] == '0' && str_N[1] == 'x')    {
        N_SEQUENTIAL_MAX = strtol(str_N,NULL,16);}
    else {
        N_SEQUENTIAL_MAX = strtol(str_N,NULL,10);}
    if(N_SEQUENTIAL_MAX < 1024) {
        fprintf(stderr,"[I] n value needs to be equal or greater than 1024, back to defaults\n");
        FLAG_N = 0;
        N_SEQUENTIAL_MAX = 0x100000000;}
    if(N_SEQUENTIAL_MAX % 1024 != 0)    {
        fprintf(stderr,"[I] n value needs to be a multiple of 1024\n");
        FLAG_N = 0;
        N_SEQUENTIAL_MAX = 0x100000000;}
  }
  printf("[+] N = %p\n",(void*)N_SEQUENTIAL_MAX);
  if(!readFileAddress(fileName))    {
            fprintf(stderr,"[E] Unexpected error\n");
            exit(EXIT_FAILURE);
  }

	
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
			s = pthread_create(&tid[i],NULL,thread_process,(void *)tt);
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
				total.Mult(2);
				pthread_mutex_lock(&bsgs_thread);
				pretotal.Set(&total);
				pretotal.Div(&seconds);
				str_seconds = seconds.GetBase10();
				str_pretotal = pretotal.GetBase10();
				str_total = total.GetBase10();
				
				if(pretotal.IsLower(&int_limits[0]))	{
				  sprintf(buffer,"\r[+] Total %s keys in %s seconds: %s keys/s\r",str_total,str_seconds,str_pretotal);
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
					if(THREADOUTPUT == 1)	{
							sprintf(buffer,"\r[+] Total %s kunci dalam %s detik: ~%s %s (%s kunci/detik)\r",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
						}
					free(str_divpretotal);
				}
				printf("%s",buffer);
				fflush(stdout);
				THREADOUTPUT = 0;			
pthread_mutex_unlock(&bsgs_thread);
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
			r = 1;
		}
		else	{
			if(rcmp < 0) {
				max = (max-half);
			}
			else	{
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
	char publickeyhashrmd160_endomorphism[12][4][20];
	bool calculate_y = FLAGSEARCH;
	Int key_mpz,keyfound,temp_stride;
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	grp->Set(dx);
// Kunci Private
	do {
			if(n_range_start.IsLower(&n_range_end))	{
				pthread_mutex_lock(&write_random);
				key_mpz.Set(&n_range_start);
				n_range_start.Add(N_SEQUENTIAL_MAX);
				pthread_mutex_unlock(&write_random);
			}
		if(continue_flag)	{
			count = 0;
			hextemp = key_mpz.GetBase16();
				printf("Base key: %s thread %i\n",hextemp,thread_number);
				fflush(stdout);
				free(hextemp);
			
			do {
				temp_stride.SetInt32(CPU_GRP_SIZE / 2);
				temp_stride.Mult(&stride);
				key_mpz.Add(&temp_stride);
	 			startP = secp->ComputePublicKey(&key_mpz);
				key_mpz.Sub(&temp_stride);

				for(i = 0; i < hLength; i++) {
					dx[i].ModSub(&Gn[i].x,&startP.x);
				}
				dx[i].ModSub(&Gn[i].x,&startP.x);
				dx[i + 1].ModSub(&_2Gn.x,&startP.x); 
				grp->ModInv();
				pts[CPU_GRP_SIZE / 2] = startP;
				for(i = 0; i<hLength; i++) {
					pp = startP;
					pn = startP;
					dy.ModSub(&Gn[i].y,&pp.y);
					_s.ModMulK1(&dy,&dx[i]);
					_p.ModSquareK1(&_s);
					pp.x.ModNeg();
					pp.x.ModAdd(&_p);
					pp.x.ModSub(&Gn[i].x);
					if(calculate_y)	{
						pp.y.ModSub(&Gn[i].x,&pp.x);
						pp.y.ModMulK1(&_s);
						pp.y.ModSub(&Gn[i].y);
					}
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
					pp_offset = CPU_GRP_SIZE / 2 + (i + 1);
					pn_offset = CPU_GRP_SIZE / 2 - (i + 1);
					pts[pp_offset] = pp;
					pts[pn_offset] = pn;
					
					if(FLAGENDOMORPHISM)	{
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

				if( calculate_y  )	{
				  endomorphism_beta[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
				  endomorphism_beta2[CPU_GRP_SIZE / 2].y.Set(&pts[CPU_GRP_SIZE / 2].y);
				}
				endomorphism_beta[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &beta);
				endomorphism_beta2[CPU_GRP_SIZE / 2].x.ModMulK1(&pts[CPU_GRP_SIZE / 2].x, &beta2);
				
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
				if(FLAGENDOMORPHISM)	{
					if( calculate_y  )	{
						endomorphism_beta[0].y.Set(&pn.y);
						endomorphism_beta2[0].y.Set(&pn.y);
					}
					endomorphism_beta[0].x.ModMulK1(&pn.x, &beta);
					endomorphism_beta2[0].x.ModMulK1(&pn.x, &beta2);
				}
				for(j = 0; j < CPU_GRP_SIZE/4;j++){
				  // bagian public key
					switch(FLAGMODE)	{
						case MODE_RMD160:{
										secp->GetHash160_fromX(P2PKH,0x02,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[0][0],(uint8_t*)publickeyhashrmd160_endomorphism[0][1],(uint8_t*)publickeyhashrmd160_endomorphism[0][2],(uint8_t*)publickeyhashrmd160_endomorphism[0][3]);
										secp->GetHash160_fromX(P2PKH,0x03,&pts[(j*4)].x,&pts[(j*4)+1].x,&pts[(j*4)+2].x,&pts[(j*4)+3].x,(uint8_t*)publickeyhashrmd160_endomorphism[1][0],(uint8_t*)publickeyhashrmd160_endomorphism[1][1],(uint8_t*)publickeyhashrmd160_endomorphism[1][2],(uint8_t*)publickeyhashrmd160_endomorphism[1][3]);
									}
						break;
					}
					// bagian proses check RMD160
					switch(FLAGMODE)	{
						case MODE_RMD160:
							for(k = 0; k < 4;k++)	{
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
					count+=4;
					temp_stride.SetInt32(4);
					temp_stride.Mult(&stride);
					key_mpz.Add(&temp_stride);
				}
				steps[thread_number]++;
				pp = startP;
				dy.ModSub(&_2Gn.y,&pp.y);
				_s.ModMulK1(&dy,&dx[i + 1]);
				_p.ModSquareK1(&_s);
				pp.x.ModNeg();
				pp.x.ModAdd(&_p);
				pp.x.ModSub(&_2Gn.x);
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


void sleep_ms(int milliseconds)	{ 
    if (milliseconds >= 1000)
      sleep(milliseconds / 1000);
    usleep((milliseconds % 1000) * 1000);
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

void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line)	{}
// Menyimpan File
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
	size_t r,raw_value_length;
	uint8_t rawvalue[50];
	char aux[100],*hextemp;
	fileDescriptor = fopen(fileName,"r");	
	if(fileDescriptor == NULL)	{
		fprintf(stderr,"[E] Error opening the file %s, line %i\n",fileName,__LINE__ - 2);
		return false;
	}
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
	MAXLENGTHADDRESS = 20;
	
	printf("[+] besar data  %" PRIu64 "%.2f MB\n",numberItems,(double)(((double) sizeof(struct address_value)*numberItems)/(double)1048576));
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
		if(r == 40 && isValidHex(aux))	{	//RMD
			hexs2bin(aux,rawvalue);				
			bloom_add(&bloom, rawvalue ,sizeof(struct address_value));
			memcpy(addressTable[i].value,rawvalue,sizeof(struct address_value));											
			i++;
			validAddress = true;
		}
	}
	N = numberItems;
	return true;
}

bool initBloomFilter(struct bloom *bloom_arg,uint64_t items_bloom)	{
	bool r = true;
	printf("[+] jumlah pencarian %" PRIu64 "\n",items_bloom);
	if(items_bloom <= 10000)	{
		if(bloom_init2(bloom_arg,10000,0.000001) == 1){
			fprintf(stderr,"[E] error max 10000 elements.\n");
			r = false;
		}
	}
	else	{
		if(bloom_init2(bloom_arg,FLAGBLOOMMULTIPLIER*items_bloom,0.000001)	== 1){
			fprintf(stderr,"[E] error kurang dari %" PRIu64 " elements.\n",items_bloom);
			r = false;
		}
	}
	printf("[+] Loading Boss... %.2f MB\n",(double)(((double) bloom_arg->bytes)/(double)1048576));
	return r;
}

