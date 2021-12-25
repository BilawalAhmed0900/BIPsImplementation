#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "curand_kernel.h"
#include <sha256.cuh>
#include <sha512.cuh>

#include <iostream>
#include <fstream>
#include <array>
#include <iomanip>
#include <chrono>

#include <argparse.hpp>
#include <utf8.h>
// #include <sqlite3.h>

enum class Languages
{
  CHINESE_SIMPLIFIED, CHINESE_TRADITIONAL,
  CZECH, ENGLISH, FRENCH, ITALIAN, 
  JAPANESE, KOREAN, PORTUGUESE, SPANISH
};

constexpr int MAX_WORDS_GENERATED = 24;
constexpr int MAX_WORD_LEN_UTF32 = 12;
constexpr int MAX_WORD_LEN_UTF8 = sizeof(char32_t) * MAX_WORD_LEN_UTF32;
constexpr int WORDS_ARRAY_LEN = 2048;
constexpr int MAX_ENTROPY_BITS = 256;
constexpr int LANGUAGES_COUNT = 10;

// char32_t WORDS_UTF32[LANGUAGES_COUNT * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF32] = { 0 };
unsigned char WORDS_UTF8[LANGUAGES_COUNT * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF8] = { 0 };

#define WORDS_UTF32_xy(words, row, col) (words[(row * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF32) + (col * MAX_WORD_LEN_UTF32)])
#define WORDS_UTF8_xy(words, row, col) (words[(row * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF8) + (col * MAX_WORD_LEN_UTF8)])

const std::array<const char*, LANGUAGES_COUNT> LANGUAGES_FILENAMES =
  {
    "chinese_simplified.txt",
    "chinese_traditional.txt",
    "czech.txt",
    "english.txt",
    "french.txt",
    "italian.txt",
    "japanese.txt",
    "korean.txt",
    "portuguese.txt",
    "spanish.txt"
  };

Languages language_str_enum(const std::string& language_str)
{
  std::string temp = language_str;
  std::transform(begin(temp), end(temp), begin(temp), [](const char& c)
    {
      return ::tolower(c);
    });

  if (temp == "english") return Languages::ENGLISH;
  else if (temp == "japanese") return Languages::JAPANESE;
  else if (temp == "korean") return Languages::KOREAN;
  else if (temp == "spanish") return Languages::SPANISH;
  else if (temp == "chinese-simplified") return Languages::CHINESE_SIMPLIFIED;
  else if (temp == "chinese-traditional") return Languages::CHINESE_SIMPLIFIED;
  else if (temp == "french") return Languages::FRENCH;
  else if (temp == "italian") return Languages::ITALIAN;
  else if (temp == "czech") return Languages::CZECH;
  else if (temp == "portuguese") return Languages::PORTUGUESE;

  return Languages::ENGLISH;
}

/*
  Sqlite3 database, not used currently
*/
/*
class Sqlite3Exception : public std::runtime_error
{
public:
  Sqlite3Exception(char* msg, bool free_msg_after_cons = false) : std::runtime_error(std::string(msg)) { if (free_msg_after_cons) sqlite3_free(msg); }
  Sqlite3Exception(int code) : std::runtime_error(sqlite3_errstr(code)) { }
};

class Sqlite3
{
public:
  Sqlite3() noexcept : db(nullptr) {}

  explicit Sqlite3(const std::string& db_filepath)
    : db(nullptr)
  {
    try
    {
      open(db_filepath);
    }
    catch (const Sqlite3Exception& err)
    {
      throw;
    }
  }

  void open(const std::string& db_filepath)
  {
    if (db != nullptr)
    {
      sqlite3_close(db);
    }

    int rc = sqlite3_open(db_filepath.c_str(), &db);
    if (rc != SQLITE_OK)
    {
      throw Sqlite3Exception(rc);
    }

    char* errmsg = nullptr;
    rc = sqlite3_exec(db, "PRAGMA synchronous = OFF", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK)
    {
      throw Sqlite3Exception(errmsg, true);
    }

    rc = sqlite3_exec(db, "PRAGMA journal_mode = MEMORY", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK)
    {
      throw Sqlite3Exception(errmsg, true);
    }
  }

  void exec(const std::string& stmt, int(*callback)(void*, int, char**, char**) = nullptr, void *first_arg = nullptr)
  {
    char* errmsg = nullptr;
    int rc = sqlite3_exec(db, stmt.c_str(), callback, first_arg, &errmsg);
    if (rc != SQLITE_OK)
    {
      throw Sqlite3Exception(errmsg, true);
    }
  }

  void insert_phrases_seed(const std::string& table_name, const std::u32string& phrases, const std::string& seed)
  {
    sqlite3_stmt* stmt;
    std::string sql_stmt = "INSERT INTO " + table_name + " VALUES (?, ?);";
    int rc = sqlite3_prepare_v2(db, sql_stmt.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK)
    {
      throw Sqlite3Exception(rc);
    }

    std::string phrases_utf8;
    utf8::utf32to8(begin(phrases), end(phrases), std::back_inserter(phrases_utf8));
    sqlite3_bind_text(stmt, 1, phrases_utf8.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, seed.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE)
    {
      sqlite3_finalize(stmt);
      throw Sqlite3Exception(rc);
    }

    sqlite3_finalize(stmt);
  }

  ~Sqlite3() noexcept
  {
    if (db != nullptr)
    {
      sqlite3_close(db);
    }
  }

private:
  ::sqlite3* db;
};
*/

void read_languages_file()
{
  size_t lang_index = 0;
  for (const char* language_filename : LANGUAGES_FILENAMES)
  {
    std::ifstream file(language_filename);
    if (!file.is_open())
    {
      throw std::runtime_error(std::string("File ") + std::string(language_filename) + std::string(" doesn't exists"));
    }

    std::string line;
    size_t index = 0;
    while (getline(file, line))
    {
      std::u32string actual_line;
      try
      {
        utf8::utf8to32(begin(line), end(line), back_inserter(actual_line));
      }
      catch (const utf8::invalid_utf8&)
      {
        throw;
      }
      catch (const utf8::invalid_code_point&)
      {
        throw;
      }
      
      // char32_t* destination_utf32 = &WORDS_UTF32[(lang_index * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF32) + (index * MAX_WORD_LEN_UTF32)];
      unsigned char* destination_utf8 = &WORDS_UTF8[(lang_index * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF8) + (index * MAX_WORD_LEN_UTF8)];
      /*
      for (size_t i = 0; i < MAX_WORD_LEN_UTF32 && i < actual_line.size(); i++)
      {
        destination_utf32[i] = actual_line.at(i);
      }
      */

      for (size_t i = 0; i < sizeof(char32_t) * MAX_WORD_LEN_UTF32 && i < line.size(); i++)
      {
        destination_utf8[i] = line.at(i);
      }
      index++;
    }

    file.close();
    lang_index++;
  }
}

void prepare_cuda();
unsigned long num_words_from_entropy_size_bits(unsigned long entropy_size_bits);
__device__ void get_random_bytes(unsigned char* buff, size_t size_bytes, size_t subsequence, size_t offset);
__device__ void hmac_sha512(const unsigned char* msg, size_t msg_len, const unsigned char* key, size_t key_len, unsigned char* output);
__device__ void PBKDF2_hmac_sha512(const unsigned char* password, size_t pass_len, const unsigned char* salt, size_t salt_len, size_t iterations, unsigned char* output);
__global__ void generate_phrases(/*char32_t* outputs_utf32, */char* outputs_utf8, size_t phrases_needed, size_t entropy_length_bits, /*char32_t* words_utf32, */char* words_utf8, Languages language);
__global__ void generate_seed(const char* outputs_utf8, size_t num_phrases, size_t phrases_in_one_sentence, const char* pass_phrase, size_t pass_phrase_size, char* row_storage, unsigned char* seeds);

#ifndef checkCudaErrors
#define checkCudaErrors(x) \
do { \
    cudaGetLastError(); \
    x; \
    cudaError_t err = cudaGetLastError(); \
    if (err != cudaSuccess) { \
        printf("GPU: cudaError %d (%s)\n", err, cudaGetErrorString(err)); \
				exit(1); \
		} \
} \
while (0);
#endif

int main(int argc, const char* argv[])
{
  argparse::ArgumentParser program("BIP-0039", "2.2");
  program.add_argument("-n", "--num").help("Number of phrases to generate").required().scan<'u', unsigned long>();
  program.add_argument("-s", "--entropy-size").help("Entropy size in bits").required().default_value(128).scan<'u', unsigned long>();
  //program.add_argument("-p", "--pass").help("Pass phrase for HMAC").required().default_value(std::string(""));
  program.add_argument("--db").help("Database file to write to").required();
  program.add_argument("--lang").help("Language to get words from").required();

  try
  {
    program.parse_args(argc, argv);
  }
  catch (const std::runtime_error& err)
  {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    std::exit(1);
  }

  unsigned long num_phrases_required = program.get<unsigned long>("-n");
  unsigned long entropy_size_bits = program.get<unsigned long>("-s");
  //std::string pass_phrase = program.get<std::string>("-p");
  std::string db_filename = program.get<std::string>("--db");
  Languages language = language_str_enum(program.get<std::string>("--lang"));

  try
  {
    read_languages_file();
  }
  catch (const std::runtime_error& err)
  {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    std::exit(1);
  }
  catch (const utf8::invalid_code_point& err)
  {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    std::exit(1);
  }
  catch (const utf8::invalid_utf8& err)
  {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    std::exit(1);
  }

  auto start_chrono = std::chrono::steady_clock::now();
  /*
  Sqlite3 db;
  try
  {
    db.open(db_filename);
    db.exec("CREATE TABLE IF NOT EXISTS BIP0039(phrases TEXT, masterkey TEXT);");
  }
  catch (const Sqlite3Exception& err)
  {
    std::cerr << err.what() << std::endl;
    std::cerr << program;
    std::exit(1);
  }
  */

  // char32_t* output_host_utf32, * output_cuda_utf32;
  char* output_host_utf8, * output_cuda_utf8;
  // char32_t* words_cuda_utf32;
  char* words_cuda_utf8;
  //output_host_utf32 = new char32_t[num_phrases_required * MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF32];
  output_host_utf8 = new char[num_phrases_required * MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF8];
  //checkCudaErrors(cudaMalloc(&output_cuda_utf32, sizeof(char32_t) * num_phrases_required * MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF32));
  checkCudaErrors(cudaMalloc(&output_cuda_utf8, sizeof(char) * num_phrases_required * MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF8));
  //checkCudaErrors(cudaMalloc(&words_cuda_utf32, sizeof(char32_t) * LANGUAGES_COUNT * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF32));
  checkCudaErrors(cudaMalloc(&words_cuda_utf8, sizeof(char) * LANGUAGES_COUNT * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF8));

  const int thread_num = 128;
  dim3 block_size(thread_num, 1, 1);
  //dim3 grid_size((num_phrases_required / thread_num) + 1 > 5000 ? 5000 : (num_phrases_required / thread_num) + 1, 1, 1);
  dim3 grid_size((num_phrases_required / thread_num) + 1, 1, 1);

  prepare_cuda();

  cudaEvent_t start, stop;
  cudaEventCreate(&start);
  cudaEventCreate(&stop);
  cudaEventRecord(start, 0);
  //checkCudaErrors(cudaMemcpy(words_cuda_utf32, WORDS_UTF32, sizeof(char32_t) * LANGUAGES_COUNT * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF32, cudaMemcpyHostToDevice));
  checkCudaErrors(cudaMemcpy(words_cuda_utf8, WORDS_UTF8, sizeof(char) * LANGUAGES_COUNT * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF8, cudaMemcpyHostToDevice));
  generate_phrases<<<grid_size, block_size>>>(/*output_cuda_utf32, */output_cuda_utf8, num_phrases_required, entropy_size_bits, /*words_cuda_utf32, */words_cuda_utf8, language);
  checkCudaErrors(cudaDeviceSynchronize());
  cudaEventRecord(stop, 0);
  cudaEventSynchronize(stop);


  float elapsed;
  cudaEventElapsedTime(&elapsed, start, stop);
  cudaEventDestroy(start);
  cudaEventDestroy(stop);

  //checkCudaErrors(cudaMemcpy(output_host_utf32, output_cuda_utf32, sizeof(char32_t) * num_phrases_required * MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF32, cudaMemcpyDeviceToHost));
  checkCudaErrors(cudaMemcpy(output_host_utf8, output_cuda_utf8, sizeof(char) * num_phrases_required * MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF8, cudaMemcpyDeviceToHost));
  
  cudaFree(words_cuda_utf8);
  //cudaFree(output_cuda_utf32);
  //cudaFree(words_cuda_utf32);

  /*
    Time is wasted to generate mnemonic + passphrase + 0 0 0 1

    Just send it one time
  */
  /*
  std::string appended_passphrase = "mnemonic" + pass_phrase;
  char* appended_passphrase_with001 = new char[appended_passphrase.size() + 4];
  for (size_t i = 0; i < appended_passphrase.size(); i++)
    appended_passphrase_with001[i] = appended_passphrase[i];

  appended_passphrase_with001[appended_passphrase.size()] = 0;
  appended_passphrase_with001[appended_passphrase.size() + 1] = 0;
  appended_passphrase_with001[appended_passphrase.size() + 2] = 0;
  appended_passphrase_with001[appended_passphrase.size() + 3] = 1;

  unsigned long words_per_phrase = num_words_from_entropy_size_bits(entropy_size_bits);
  unsigned char* output_seeds_host, *output_seeds_cuda;
  char* pass_phrase_cuda_with001;
  char* row_storage_cuda;
  output_seeds_host = new unsigned char[num_phrases_required * SHA512_DIGEST_SIZE];
  checkCudaErrors(cudaMalloc(&output_seeds_cuda, sizeof(unsigned char) * num_phrases_required * SHA512_DIGEST_SIZE));
  checkCudaErrors(cudaMalloc(&pass_phrase_cuda_with001, appended_passphrase.size() + 4 + 1));
  checkCudaErrors(cudaMalloc(&row_storage_cuda, sizeof(char) * num_phrases_required * (MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF8 + MAX_WORDS_GENERATED)));
  checkCudaErrors(cudaMemcpy(pass_phrase_cuda_with001, appended_passphrase_with001, appended_passphrase.size() + 4, cudaMemcpyHostToDevice));

  cudaEventCreate(&start);
  cudaEventCreate(&stop);
  cudaEventRecord(start, 0);
  generate_seed<<<grid_size, block_size>>>(output_cuda_utf8, num_phrases_required, words_per_phrase, pass_phrase_cuda_with001, appended_passphrase.size() + 4, row_storage_cuda, output_seeds_cuda);
  checkCudaErrors(cudaDeviceSynchronize());
  cudaEventRecord(stop, 0);
  cudaEventSynchronize(stop);

  float elapsed_seed;
  cudaEventElapsedTime(&elapsed_seed, start, stop);
  cudaEventDestroy(start);
  cudaEventDestroy(stop);

  checkCudaErrors(cudaMemcpy(output_seeds_host, output_seeds_cuda, num_phrases_required * SHA512_DIGEST_SIZE, cudaMemcpyDeviceToHost));
  */

  /*
    Using FILE* as it is faster to write hex many many times.
  */
  unsigned long words_per_phrase = num_words_from_entropy_size_bits(entropy_size_bits);
  std::ofstream file(db_filename, std::ios::app);
  if (file.is_open())
  {
    for (size_t i = 0; i < num_phrases_required; i++)
    {
      for (size_t j = 0; j < words_per_phrase; j++)
      {
        char* row_utf8 = &output_host_utf8[i * MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF8];
        char* source_utf8 = &row_utf8[j * MAX_WORD_LEN_UTF8];

        file << source_utf8;
        if (j != words_per_phrase - 1) file << ' ';
      }
      file << '\n';
    }

    file.close();
  }

  //delete[] output_host_utf32;
  delete[] output_host_utf8;
  //delete[] output_seeds_host;
  //delete[] appended_passphrase_with001;
  //cudaFree(output_seeds_cuda);
  //cudaFree(pass_phrase_cuda_with001);
  cudaFree(output_cuda_utf8);
  //cudaFree(row_storage_cuda);

  auto end_chrono = std::chrono::steady_clock::now();

  std::cout << "Time taken (kernel phrases): " << elapsed << " ms" << std::endl;
  //std::cout << "Time taken (kernel seed): " << elapsed_seed << " ms" << std::endl;
  std::cout << "Time taken (overall): " << std::chrono::duration_cast<std::chrono::milliseconds>(end_chrono - start_chrono).count() << " ms" << std::endl;
  return 0;
}

void prepare_cuda()
{
  checkCudaErrors(cudaMemcpyToSymbol(sha256_dev_k, sha256_host_k, sizeof(sha256_host_k), 0, cudaMemcpyHostToDevice));
  checkCudaErrors(cudaMemcpyToSymbol(sha512_dev_k, sha512_host_k, sizeof(sha512_host_k), 0, cudaMemcpyHostToDevice));
}

unsigned long num_words_from_entropy_size_bits(unsigned long entropy_size_bits)
{
  unsigned long indices_length = entropy_size_bits + (entropy_size_bits >> 5u);
  if (indices_length % 11 != 0)
  {
    indices_length += 11 - (indices_length % 11);
  }
  unsigned long num_words = indices_length / 11;

  return num_words;
}

__device__ void get_random_bytes(unsigned char* buff, size_t size_bytes, size_t subsequence, size_t offset)
{
  curandStateMRG32k3a_t state;
  size_t bytes_written;
  uint32_t rand_word;
  size_t remaining;

  size_t num_32_bits = size_bytes / sizeof(uint32_t);

  curand_init(clock64(), subsequence, offset, &state);
  bytes_written = 0;
  for (size_t i = 0; i < num_32_bits; i++)
  {
    rand_word = curand(&state);
    buff[bytes_written++] = (rand_word >> 24u) & 0xffu;
    buff[bytes_written++] = (rand_word >> 16u) & 0xffu;
    buff[bytes_written++] = (rand_word >> 8u) & 0xffu;
    buff[bytes_written++] = (rand_word >> 0u) & 0xffu;
  }

  remaining = size_bytes - bytes_written;
  rand_word = curand(&state);
  for (size_t i = 0; i < remaining; i++)
  {
    buff[bytes_written++] = (rand_word >> (24u - (i * 8))) & 0xffu;
  }
}

__global__ void generate_phrases(/*char32_t* outputs_utf32, */char* outputs_utf8, size_t phrases_needed, size_t entropy_length_bits, /*char32_t* words_utf32, */char* words_utf8, Languages language)
{
  size_t current_index = blockDim.x * blockIdx.x + threadIdx.x;
  if (current_index >= phrases_needed) return;

  if (entropy_length_bits != 128 && entropy_length_bits != 160 &&
    entropy_length_bits != 192 && entropy_length_bits != 224 &&
    entropy_length_bits != 256)
  {
    return;
  }

  size_t stride_amount = gridDim.x * blockDim.x;
  size_t previous_generated_sequence_bytes = 0;
  for (; current_index < phrases_needed; current_index += stride_amount)
  {
    unsigned char entropy_bytes[MAX_ENTROPY_BITS >> 3u] = { 0 };
    size_t entropy_length_bytes = entropy_length_bits >> 3u;
    get_random_bytes(entropy_bytes, entropy_length_bytes, current_index, previous_generated_sequence_bytes);
    previous_generated_sequence_bytes += entropy_length_bytes;

    unsigned char sha256[SHA256_DIGEST_SIZE] = { 0 };
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, entropy_bytes, entropy_length_bytes);
    sha256_final(&ctx, sha256);

    size_t indices_length = entropy_length_bits + (entropy_length_bits >> 5u);
    if (indices_length % 11 != 0)
    {
      indices_length += 11 - (indices_length % 11);
    }

    unsigned char indices_bits[MAX_ENTROPY_BITS + (MAX_ENTROPY_BITS >> 5u)] = { 0 };
    size_t written_bits_to_indices = 0;
    for (size_t i = 0; i < entropy_length_bytes; i++)
    {
      indices_bits[written_bits_to_indices++] = (entropy_bytes[i] >> 7u) & 1u;
      indices_bits[written_bits_to_indices++] = (entropy_bytes[i] >> 6u) & 1u;
      indices_bits[written_bits_to_indices++] = (entropy_bytes[i] >> 5u) & 1u;
      indices_bits[written_bits_to_indices++] = (entropy_bytes[i] >> 4u) & 1u;
      indices_bits[written_bits_to_indices++] = (entropy_bytes[i] >> 3u) & 1u;
      indices_bits[written_bits_to_indices++] = (entropy_bytes[i] >> 2u) & 1u;
      indices_bits[written_bits_to_indices++] = (entropy_bytes[i] >> 1u) & 1u;
      indices_bits[written_bits_to_indices++] = (entropy_bytes[i] >> 0u) & 1u;
    }

    size_t ahead = written_bits_to_indices + (entropy_length_bits >> 5u);
    for (size_t i = 0; i < SHA256_DIGEST_SIZE && written_bits_to_indices < ahead; i++)
    {
      for (size_t j = 0; j < 8 && written_bits_to_indices < ahead; j++)
      {
        indices_bits[written_bits_to_indices++] = (sha256[i] >> (7u - j)) & 1u;
      }
    }

    for (; written_bits_to_indices < indices_length; )
    {
      indices_bits[written_bits_to_indices++] = 0;
    }

    for (size_t i = 0; i < indices_length / 11; i++)
    {
      size_t index = (indices_bits[(i * 11) + 0] << 10u);
      index |= (indices_bits[(i * 11) + 1] << 9u);
      index |= (indices_bits[(i * 11) + 2] << 8u);
      index |= (indices_bits[(i * 11) + 3] << 7u);
      index |= (indices_bits[(i * 11) + 4] << 6u);
      index |= (indices_bits[(i * 11) + 5] << 5u);
      index |= (indices_bits[(i * 11) + 6] << 4u);
      index |= (indices_bits[(i * 11) + 7] << 3u);
      index |= (indices_bits[(i * 11) + 8] << 2u);
      index |= (indices_bits[(i * 11) + 9] << 1u);
      index |= (indices_bits[(i * 11) + 10] << 0u);

      /*
      char32_t* destination_row_utf32 = &outputs_utf32[(current_index * MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF32)];
      char32_t* destination_utf32 = &destination_row_utf32[(i * MAX_WORD_LEN_UTF32)];
      char32_t* source_row_utf32 = &words_utf32[((size_t)language * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF32)];
      char32_t* source_utf32 = &source_row_utf32[(index * MAX_WORD_LEN_UTF32)];
      for (size_t j = 0; j < MAX_WORD_LEN_UTF32; j++)
      {
        destination_utf32[j] = source_utf32[j];
      }
      */

      char *destination_row_utf8 = &outputs_utf8[(current_index * MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF8)];
      char *destination_utf8 = &destination_row_utf8[(i * MAX_WORD_LEN_UTF8)];
      char *source_row_utf8 = &words_utf8[((size_t)language * WORDS_ARRAY_LEN * MAX_WORD_LEN_UTF8)];
      char* source_utf8 = &source_row_utf8[(index * MAX_WORD_LEN_UTF8)];
      for (size_t j = 0; j < MAX_WORD_LEN_UTF8; j++)
      {
        destination_utf8[j] = source_utf8[j];
      }
    }
  }
}

__device__ size_t strlen_char(const char* str)
{
  size_t result = 0;
  while (*str)
  {
    str++;
    result++;
  }

  return result;
}

__device__ void prepend_mnemonic(char* prepended_passphrase, const char* passphrase)
{
  size_t written = 0;
  prepended_passphrase[written++] = 'm';
  prepended_passphrase[written++] = 'n';
  prepended_passphrase[written++] = 'e';
  prepended_passphrase[written++] = 'm';
  prepended_passphrase[written++] = 'o';
  prepended_passphrase[written++] = 'n';
  prepended_passphrase[written++] = 'i';
  prepended_passphrase[written++] = 'c';

  size_t len = strlen_char(passphrase);
  for (size_t i = 0; i < len; i++)
    prepended_passphrase[written++] = passphrase[i];

  prepended_passphrase[written] = '\0';
}

__device__ void join_phrases(char *joined_phrases, const char* row, size_t phrases_in_one_sentence)
{
  size_t written = 0;
  for (size_t i = 0; i < phrases_in_one_sentence; i++)
  {
    size_t len = strlen_char(row);
    for (size_t j = 0; j < len; j++)
    {
      joined_phrases[written++] = row[j];
    }

    if (i != phrases_in_one_sentence - 1) joined_phrases[written++] = ' ';
    row += MAX_WORD_LEN_UTF32 * sizeof(char32_t);
  }
}

__global__ void generate_seed(const char* outputs_utf8, size_t num_phrases, size_t phrases_in_one_sentence, const char* pass_phrase_with001, size_t pass_phrase_size, char *row_storage, unsigned char* seeds)
{
  size_t current_index = blockDim.x * blockIdx.x + threadIdx.x;
  if (current_index >= num_phrases) return;

  size_t stride_amount = gridDim.x * blockDim.x;
  char* this_row = &row_storage[current_index * (MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF8 + MAX_WORDS_GENERATED)];
  for (; current_index < num_phrases; current_index += stride_amount)
  {
    const char* row = &outputs_utf8[(current_index * MAX_WORDS_GENERATED * MAX_WORD_LEN_UTF8)];
    
    size_t written = 0;
    for (size_t i = 0; i < phrases_in_one_sentence; i++)
    {
      const char* source = &row[i * MAX_WORD_LEN_UTF8];
      size_t len = strlen_char(source);

      for (size_t j = 0; j < len; j++)
        this_row[written++] = source[j];

      if (i != phrases_in_one_sentence - 1) this_row[written++] = ' ';
    }
    this_row[written] = '\0';

    unsigned char seed[SHA512_DIGEST_SIZE] = { 0 };
    PBKDF2_hmac_sha512((const unsigned char*)this_row, written, (const unsigned char*)pass_phrase_with001, pass_phrase_size, 2048, seed);

    unsigned char* output_seed = &seeds[current_index * SHA512_DIGEST_SIZE];
    for (size_t i = 0; i < SHA512_DIGEST_SIZE; i++)
    {
      output_seed[i] = seed[i];
    }
  }
}

__device__ void hmac_sha512(const unsigned char* msg, size_t msg_len, const unsigned char* key, size_t key_len, unsigned char* output)
{
  unsigned char hashed_key[SHA512_BLOCK_SIZE] = { 0 };
  if (key_len > SHA512_BLOCK_SIZE)
  {
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, key, key_len);
    sha512_final(&ctx, hashed_key);

    key_len = SHA512_DIGEST_SIZE;
  }
  else
  {
    for (size_t i = 0; i < key_len; i++)
    {
      hashed_key[i] = key[i];
    }
  }

  unsigned char o_key_pad[SHA512_BLOCK_SIZE] = { 0 };
  unsigned char i_key_pad[SHA512_BLOCK_SIZE] = { 0 };
  for (size_t i = 0; i < SHA512_BLOCK_SIZE; i++)
  {
    o_key_pad[i] = hashed_key[i] ^ 0x5c;
    i_key_pad[i] = hashed_key[i] ^ 0x36;
  }

  unsigned char o_key_pad_hash[SHA512_DIGEST_SIZE] = { 0 };

  SHA512_CTX ctx;
  sha512_init(&ctx);
  sha512_update(&ctx, i_key_pad, SHA512_BLOCK_SIZE);
  sha512_update(&ctx, msg, msg_len);
  sha512_final(&ctx, o_key_pad_hash);

  sha512_init(&ctx);
  sha512_update(&ctx, o_key_pad, SHA512_BLOCK_SIZE);
  sha512_update(&ctx, o_key_pad_hash, SHA512_DIGEST_SIZE);
  sha512_final(&ctx, output);
}

__device__ void append_one(const unsigned char* salt, size_t salt_len, unsigned char* output)
{
  for (size_t i = 0; i < salt_len; i++)
  {
    output[i] = salt[i];
  }

  output[salt_len] = 0;
  output[salt_len + 1] = 0;
  output[salt_len + 2] = 0;
  output[salt_len + 3] = 1;
}

__device__ void PBKDF2_hmac_sha512(const unsigned char* password, size_t pass_len, const unsigned char* salt_with001, size_t salt_len, size_t iterations, unsigned char *output)
{
  unsigned char Us[2 * SHA512_DIGEST_SIZE] = { 0 };
  hmac_sha512(salt_with001, salt_len, password, pass_len, &Us[0 * SHA512_DIGEST_SIZE]);
  for (size_t i = 0; i < SHA512_DIGEST_SIZE; i++)
  {
    output[i] = Us[i];
  }

  for (size_t i = 1; i < iterations; i++)
  {
    hmac_sha512(&Us[0 * SHA512_DIGEST_SIZE], SHA512_DIGEST_SIZE, password, pass_len, &Us[1 * SHA512_DIGEST_SIZE]);
    for (size_t j = 0; j < SHA512_DIGEST_SIZE; j++)
    {
      Us[j] = Us[j + SHA512_DIGEST_SIZE];
      output[j] ^= Us[j + SHA512_DIGEST_SIZE];
    }
  }
}
