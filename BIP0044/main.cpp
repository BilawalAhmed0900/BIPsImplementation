#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <memory>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>

#include <argparse.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#include <chrono>

#define OSSL_DEPRECATEDIN_3_0
#include <openssl/ripemd.h>
#undef OSSL_DEPRECATEDIN_3_0

struct KeyCombination
{
  std::string address;
  std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)> private_key;
  std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)> public_key;
  std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)> chain_code;
};

class thread_class
{
  EC_GROUP* group;
  BN_CTX* ctx;

public:
  thread_class()
  {
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    ctx = BN_CTX_new();

    if (group == nullptr || ctx == nullptr)
    {
      throw std::runtime_error("Cannot allocate EC_GROUP or BN_CTX");
    }
  }

  thread_class(const thread_class& th)
  {
    group = EC_GROUP_dup(th.group);
    ctx = BN_CTX_new();

    if (group == nullptr || ctx == nullptr)
    {
      throw std::runtime_error("Cannot allocate EC_GROUP or BN_CTX");
    }
  }

  thread_class(thread_class&& th) noexcept
  {
    group = th.group;
    ctx = th.ctx;

    th.group = nullptr;
    th.ctx = nullptr;
  }

  ~thread_class()
  {
    if (group != nullptr)
      EC_GROUP_free(group);

    if (ctx != nullptr)
      BN_CTX_free(ctx);
  }

  static std::shared_ptr<spdlog::logger> logger;
  void operator()(const std::vector<std::string>& input_buffer, std::map<std::string, KeyCombination>& output_buffer,
    size_t from, size_t to, const std::string& pass_phrase, size_t child_keys_num) const;
};

size_t read_input(const std::string& file_path, std::vector<std::string> &input_buffer, size_t capacity);
template <size_t N> std::string as_hex(const std::array<uint8_t, N>& a);

int main(int argc, const char* argv[])
{
  argparse::ArgumentParser program("BIP0044", "0.2");
  program.add_argument("-n", "--num-input").help("Number of addresses to generate, i.e., number of phrases to read from input").required().scan<'u', unsigned long>();
  program.add_argument("-th", "--num-threads").help("Number of threads to use").required().scan<'u', unsigned long>().default_value(static_cast<unsigned long>(8u));
  program.add_argument("-c", "--childs").help("Childs key per master key (address_index)").required().scan<'u', unsigned long>();
  program.add_argument("-i", "--input").help("The input file to read from").required();
  program.add_argument("-p", "--pass-phrase").help("The pass phrase for binary seed generation").required().default_value(std::string(""));
  program.add_argument("-o", "--output").help("The output file to write to").required();

  std::shared_ptr<spdlog::logger> logger = spdlog::stdout_logger_mt(std::string("LOGGER"));
  logger->set_pattern("[thread %t] %v");

  try
  {
    program.parse_args(argc, argv);
  }
  catch (const std::runtime_error& err)
  {
    logger->warn(err.what());
    std::cerr << program << std::endl;
    std::exit(1);
  }

  std::string input_file_path = program.get<std::string>("-i");
  std::string output_file_path = program.get<std::string>("-o");
  std::string pass_phrase = program.get<std::string>("-p");
  unsigned long num_input = program.get<unsigned long>("-n");
  unsigned long num_threads = program.get<unsigned long>("-th");
  unsigned long childs = program.get<unsigned long>("-c");

  std::vector<std::string> input_buffer;
  std::map<std::string, KeyCombination> output_buffer;

  input_buffer.reserve(num_input);
  size_t read_len;
  try
  {
    read_len = read_input(input_file_path, input_buffer, num_input);
  }
  catch (const std::runtime_error& err)
  {
    logger->warn(err.what());
    std::cerr << program << std::endl;
    std::exit(1);
  }

  thread_class::logger = logger;
  if (read_len != num_input)
  {
    logger->warn("The number of phrases read is not equal to that supplied in the parameters");
  }

  std::vector<std::thread> threads;
  threads.reserve(num_threads);

  constexpr const char* MNEMONIC_LITERAL = "mnemonic";
  pass_phrase.insert(0, MNEMONIC_LITERAL);
  size_t portion_per_thread = read_len / num_threads;
  if (portion_per_thread == 0) portion_per_thread = read_len;

  auto start = std::chrono::high_resolution_clock::now();
  for (unsigned long i = 0; i < num_threads; i++)
  {
    size_t from = (i * portion_per_thread);
    size_t to = ((i + 1) * portion_per_thread);
    if (to > read_len) to = read_len;

    threads.emplace_back(thread_class(), std::cref(input_buffer), std::ref(output_buffer), from, to, std::cref(pass_phrase), (size_t)childs);
    if (to == read_len) break;
  }
  for (std::thread& thr : threads) thr.join();
  auto end = std::chrono::high_resolution_clock::now();

  std::ofstream out(output_file_path);
  if (!out.is_open())
  {
    logger->warn(std::string("Cannot open output file \'") + output_file_path + std::string("\'"));
  }
  else
  {
    if (out.tellp() == 0)
    {
      out << "phrase,address,private key,chain code,public key\n";
    }

    for (const auto& pair : output_buffer)
    {
      out << pair.first << ',' << pair.second.address << ',' << as_hex(pair.second.private_key) << ',' << as_hex(pair.second.chain_code) << ',' << as_hex(pair.second.public_key) << '\n';
    }
    out.close();
  }

  double time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
  std::cout << "Time taken: " << time_taken << " ms\n";
  return 0;
}

size_t read_input(const std::string& file_path, std::vector<std::string>& input_buffer, size_t capacity)
{
  std::ifstream file(file_path);
  if (!file.is_open())
  {
    throw std::runtime_error("Input file not found");
  }

  size_t index = 0;
  std::string line;
  while (true)
  {
    if (index >= capacity) break;
    if (!std::getline(file, line)) break;

    input_buffer.push_back(line);
    index++;
  }

  file.close();
  return index;
}

/*
  Most significate byte first integers
*/
int compare_two_big_num(const unsigned char* a, const unsigned char* b, size_t len_a, size_t len_b)
{
  if (len_a < len_b) return -1;
  if (len_a > len_b) return 1;

  for (size_t i = 0; i < len_a; i++)
  {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }

  return 0;
}

template <size_t N>
std::string as_hex(const std::array<uint8_t, N>& a)
{
  std::stringstream ss;
  for (size_t i = 0; i < N; i++)
  {
    ss << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)a[i];
  }

  return ss.str();
}

int generate_binary_seed(const std::string& phrases, const std::string& pass_phrase, std::array<uint8_t, SHA512_DIGEST_LENGTH>& seed_bytes)
{
  std::array<uint8_t, SHA512_DIGEST_LENGTH> result{ 0 };
  int result_PBKDF2 = PKCS5_PBKDF2_HMAC(phrases.c_str(), -1, (const uint8_t*)pass_phrase.c_str(), pass_phrase.size(), 2048, EVP_sha512(), SHA512_DIGEST_LENGTH, &seed_bytes[0]);
  return result_PBKDF2;
}

uint8_t* generate_bitcoin_hmac_sha512(const std::array<uint8_t, SHA512_DIGEST_LENGTH>& seed_bytes, std::array<uint8_t, SHA512_DIGEST_LENGTH>& I)
{
  constexpr const char I_Key[] = "Bitcoin seed";
  constexpr int I_Key_Len = sizeof(I_Key) - 1;

  unsigned int I_len = I.max_size();
  uint8_t* result_hmac = HMAC(EVP_sha512(), I_Key, I_Key_Len, &seed_bytes[0], SHA512_DIGEST_LENGTH, &I[0], &I_len);
  return result_hmac;
}

bool is_key_good(const std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& key)
{
  constexpr uint8_t N[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41";
  constexpr uint8_t ZERO[(SHA512_DIGEST_LENGTH >> 1u)] = { 0 };

  if (compare_two_big_num(key.data(), ZERO, (SHA512_DIGEST_LENGTH >> 1u), (SHA512_DIGEST_LENGTH >> 1u)) == 0 ||
    compare_two_big_num(key.data(), N, (SHA512_DIGEST_LENGTH >> 1u), (SHA512_DIGEST_LENGTH >> 1u)) == 1)
  {
    return false;
  }

  return true;
}

constexpr int SERIALIZED_KEY_LEN = 78;
std::array<uint8_t, SERIALIZED_KEY_LEN> serialize_master_key(const std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& normal_key,
  const std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& chain_code, uint8_t depth, bool is_private)
{
  std::array<uint8_t, SERIALIZED_KEY_LEN> result{ 0 };
  if (!is_private)
  {
    result[0] = 0x04; result[1] = 0x88; result[2] = 0xB2; result[3] = 0x1E;
  }
  else
  {
    result[0] = 0x04; result[1] = 0x88; result[2] = 0xAD; result[3] = 0xE4;
  }
  result[4] = depth;

  result[5] = 0x00; result[6] = 0x00; result[7] = 0x00; result[8] = 0x00;
  result[9] = 0x00; result[10] = 0x00; result[11] = 0x00; result[12] = 0x00;

  size_t written = 13;
  for (size_t i = 0; i < chain_code.size(); i++)
  {
    result[written + i] = chain_code[i];
  }
  written += chain_code.size();

  result[written++] = 0x00;
  for (size_t i = 0; i < normal_key.size(); i++)
  {
    result[written + i] = normal_key[i];
  }
  return result;
}

template <size_t N>
std::string encode_base58(const std::array<uint8_t, N>& data)
{
  long zero_counter = 0;
  constexpr int b56_bytes_Len = (N * 138 / 100) + 1;
  std::array<char, b56_bytes_Len + 1> b58_bytes{ 0 };

  size_t i = 0;
  while (i < N && data[i] == 0x00) zero_counter++, i++;
  for (; i < N; i++)
  {
    long carry = data[i];
    for (long long j = b56_bytes_Len - 1; j >= 0 && carry >= 0; j--)
    {
      carry += b58_bytes[j] * 256;
      b58_bytes[j] = carry % 58;
      carry /= 58;
    }
  }

  constexpr const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  std::stringstream ss;

  i = 0;
  while (i < b56_bytes_Len && b58_bytes[i] == 0) i++;
  for (size_t j = i; j < b56_bytes_Len; j++) b58_bytes[j] = BASE58_ALPHABET[b58_bytes[j]];

  return std::string(zero_counter, '1') + std::string(b58_bytes.data() + i);
}

std::string encode_base58(const std::array<uint8_t, SERIALIZED_KEY_LEN>& serialized_key)
{
  uint8_t sha256_first[SHA256_DIGEST_LENGTH] = { 0 }, sha256_second[SHA256_DIGEST_LENGTH] = { 0 };
  uint8_t* result_sha256 = SHA256(serialized_key.data(), SERIALIZED_KEY_LEN, sha256_first);
  if (result_sha256 == nullptr) return "";

  result_sha256 = SHA256(sha256_first, SHA256_DIGEST_LENGTH, sha256_second);
  if (result_sha256 == nullptr) return "";

  std::array<uint8_t, SERIALIZED_KEY_LEN + 4> checksum_appended_key{ 0 };

  for (size_t i = 0; i < SERIALIZED_KEY_LEN; i++) checksum_appended_key[i] = serialized_key[i];
  checksum_appended_key[SERIALIZED_KEY_LEN + 0] = sha256_second[0];
  checksum_appended_key[SERIALIZED_KEY_LEN + 1] = sha256_second[1];
  checksum_appended_key[SERIALIZED_KEY_LEN + 2] = sha256_second[2];
  checksum_appended_key[SERIALIZED_KEY_LEN + 3] = sha256_second[3];

  long zero_counter = 0;
  constexpr int b56_bytes_Len = ((SERIALIZED_KEY_LEN + 4) * 138 / 100) + 1;
  std::array<char, b56_bytes_Len + 1> b58_bytes{ 0 };

  size_t i = 0;
  while (i < SERIALIZED_KEY_LEN + 4 && checksum_appended_key[i] == 0x00) zero_counter++, i++;
  for (; i < SERIALIZED_KEY_LEN + 4; i++)
  {
    long carry = checksum_appended_key[i];
    for (long long j = b56_bytes_Len - 1; j >= 0 && carry >= 0; j--)
    {
      carry += b58_bytes[j] * 256;
      b58_bytes[j] = carry % 58;
      carry /= 58;
    }
  }

  constexpr const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  std::stringstream ss;
  
  i = 0;
  while (i < b56_bytes_Len && b58_bytes[i] == 0) i++;
  for (size_t j = i; j < b56_bytes_Len; j++) b58_bytes[j] = BASE58_ALPHABET[b58_bytes[j]];

  return std::string(zero_counter, '1') + std::string(b58_bytes.data() + i);
}

int point(const EC_GROUP* group,
  const std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& p,
  std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& output,
  bool& is_y_odd)
{
  BIGNUM* p_num = BN_bin2bn(p.data(), p.size(), nullptr);
  if (p_num == nullptr)
  {
    return -1;
  }

  EC_POINT* result_point = EC_POINT_new(group);
  if (result_point == nullptr)
  {
    BN_free(p_num);
    return -1;
  }

  int result_EC_POINT_mul = EC_POINT_mul(group, result_point, p_num, nullptr, nullptr, nullptr);
  if (result_EC_POINT_mul != 1)
  {
    BN_free(p_num);
    EC_POINT_free(result_point);
    return -1;
  }

  BIGNUM* x = BN_new(), *y = BN_new();
  if (x == nullptr || y == nullptr)
  {
    BN_free(p_num);
    EC_POINT_free(result_point);

    if (x) BN_free(x);
    if (y) BN_free(y);
    return -1;
  }

  int result_get_coordinates = EC_POINT_get_affine_coordinates(group, result_point, x, y, nullptr);
  if (result_get_coordinates != 1)
  {
    BN_free(p_num);
    EC_POINT_free(result_point);
    BN_free(x);
    BN_free(y);

    return -1;
  }

  is_y_odd = BN_is_odd(y) == 1 ? true : false;
  if (BN_num_bytes(x) > (SHA512_DIGEST_LENGTH >> 1u))
  {
    BN_free(p_num);
    EC_POINT_free(result_point);
    BN_free(x);
    BN_free(y);

    return -1;
  }
  BN_bn2bin(x, output.data());

  BN_free(p_num);
  EC_POINT_free(result_point);
  BN_free(x);
  BN_free(y);
  return 0;
}

int get_child_key(BN_CTX *ctx,
  const std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& Il,
  const std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& k_par,
  std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& k_i)
{
  constexpr uint8_t N_array[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41";
  static BIGNUM* N = BN_bin2bn(N_array, sizeof(N_array) - 1, nullptr);
  if (N == nullptr)
  {
    return -1;
  }

  BIGNUM *k_par_num = BN_bin2bn(k_par.data(), k_par.size(), nullptr);
  if (k_par_num == nullptr)
  {
    return -1;
  }

  BIGNUM *Il_num = BN_bin2bn(Il.data(), Il.size(), nullptr);
  if (Il_num == nullptr)
  {
    BN_free(k_par_num);
    return -1;
  }

  BIGNUM *Il_plus_kpar_mod_N = BN_new();
  if (Il_plus_kpar_mod_N == nullptr)
  {
    BN_free(Il_num);
    BN_free(k_par_num);
    return -1;
  }

  if (BN_mod_add(Il_plus_kpar_mod_N, Il_num, k_par_num, N, ctx) != 1)
  {
    BN_free(Il_plus_kpar_mod_N);
    BN_free(Il_num);
    BN_free(k_par_num);
    return -1;
  }

  if (BN_num_bytes(Il_plus_kpar_mod_N) > (SHA512_DIGEST_LENGTH >> 1u))
  {
    BN_free(Il_plus_kpar_mod_N);
    BN_free(Il_num);
    BN_free(k_par_num);
    return -1;
  }

  if (BN_bn2bin(Il_plus_kpar_mod_N, k_i.data()) == 0)
  {
    BN_free(Il_plus_kpar_mod_N);
    BN_free(Il_num);
    BN_free(k_par_num);
    return -1;
  }

  BN_free(Il_plus_kpar_mod_N);
  BN_free(Il_num);
  BN_free(k_par_num);
  return 0;
}

int derive_child_key_private(
  const EC_GROUP *group,
  BN_CTX *ctx,
  const std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& normal_key,
  const std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& chain_code,
  std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& derived_normal_key,
  std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& derived_chain_code,
  uint32_t index)
{
  std::array<uint8_t, SHA512_DIGEST_LENGTH> I;
  unsigned int I_len = SHA512_DIGEST_LENGTH;

  std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)> normal_key_copy;
  for (size_t i = 0; i < (SHA512_DIGEST_LENGTH >> 1u); i++)
    normal_key_copy[i] = normal_key[i];

  if ((index & ((uint32_t)0x80000000ull)) != 0)
  {
    std::array<uint8_t, 1 + (SHA512_DIGEST_LENGTH >> 1u) + sizeof(uint32_t)> data{ 0 };
    
    for (size_t i = 0; i < (SHA512_DIGEST_LENGTH >> 1u); i++)
    {
      data[1 + i] = normal_key[i];
    }
    data[1 + (SHA512_DIGEST_LENGTH >> 1u) + 0] = (index >> 24u) & 0xff;
    data[1 + (SHA512_DIGEST_LENGTH >> 1u) + 1] = (index >> 16u) & 0xff;
    data[1 + (SHA512_DIGEST_LENGTH >> 1u) + 2] = (index >> 8u) & 0xff;
    data[1 + (SHA512_DIGEST_LENGTH >> 1u) + 3] = (index >> 0u) & 0xff;

    
    uint8_t* result_hmac = HMAC(EVP_sha512(), chain_code.data(), chain_code.size(), data.data(), data.size(), I.data(), &I_len);
    if (result_hmac == nullptr)
    {
      return -1;
    }
  }
  else
  {
    std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)> serialized_point{ 0 };
    bool is_y_odd;
    int result_point = point(group, normal_key, serialized_point, is_y_odd);
    if (result_point != 0)
    {
      return -1;
    }

    std::array<uint8_t, 1 + (SHA512_DIGEST_LENGTH >> 1u) + 4> data{ 0 };
    data[0] = 0x02 + (is_y_odd ? 0x01 : 0x00);
    for (size_t i = 0; i < (SHA512_DIGEST_LENGTH >> 1u); i++)
    {
      data[1 + i] = serialized_point[i];
    }

    data[1 + (SHA512_DIGEST_LENGTH >> 1u) + 0] = (index >> 24u) & 0xff;
    data[1 + (SHA512_DIGEST_LENGTH >> 1u) + 1] = (index >> 16u) & 0xff;
    data[1 + (SHA512_DIGEST_LENGTH >> 1u) + 2] = (index >> 8u) & 0xff;
    data[1 + (SHA512_DIGEST_LENGTH >> 1u) + 3] = (index >> 0u) & 0xff;
    uint8_t* result_hmac = HMAC(EVP_sha512(), chain_code.data(), chain_code.size(), data.data(), data.size(), I.data(), &I_len);
    if (result_hmac == nullptr)
    {
      return -1;
    }
  }

  for (size_t i = 0; i < (SHA512_DIGEST_LENGTH >> 1u); i++)
  {
    derived_normal_key[i] = I[i];
  }
  for (size_t i = 0; i < (SHA512_DIGEST_LENGTH >> 1u); i++)
  {
    derived_chain_code[i] = I[(SHA512_DIGEST_LENGTH >> 1u) + i];
  }

  if (!is_key_good(derived_normal_key))
  {
    return -1;
  }

  if (get_child_key(ctx, derived_normal_key, normal_key_copy, derived_normal_key) != 0)
  {
    return -1;
  }

  if (!is_key_good(derived_normal_key))
  {
    return -1;
  }
  return 0;
}

int derive_child_key_public(
  const EC_GROUP* group,
  BN_CTX* ctx,
  const std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& normal_key,
  std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& derived_normal_key,
  bool &is_y_odd)
{
  int result_point = point(group, normal_key, derived_normal_key, is_y_odd);
  if (result_point != 0)
  {
    return -1;
  }

  return 0;
}

std::string convert_private_key_to_address(
  const EC_GROUP* group,
  BN_CTX* ctx,
  const std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)>& normal_key,
  std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)> &stored_public_key
)
{
  bool is_y_odd;
  if (derive_child_key_public(group, ctx, normal_key, stored_public_key, is_y_odd) != 0)
  {
    return "";
  }

  std::array<uint8_t, 1 + (SHA512_DIGEST_LENGTH >> 1u)> appended_public_key;
  appended_public_key[0] = 0x02 + (is_y_odd ? 0x01 : 0x00);
  for (size_t i = 0; i < (SHA512_DIGEST_LENGTH >> 1u); i++)
  {
    appended_public_key[1 + i] = stored_public_key[i];
  }

  std::array<uint8_t, SHA256_DIGEST_LENGTH> sha256_first, sha256_second;
  if (SHA256(appended_public_key.data(), appended_public_key.size(), sha256_first.data()) == nullptr)
  {
    return "";
  }

  std::array<uint8_t, 1 + RIPEMD160_DIGEST_LENGTH + 4> ripemd160;
  if (RIPEMD160(sha256_first.data(), SHA256_DIGEST_LENGTH, ripemd160.data() + 1) == nullptr)
  {
    return "";
  }
  ripemd160[0] = 0x00;

  if (SHA256(ripemd160.data(), 1 + RIPEMD160_DIGEST_LENGTH, sha256_first.data()) == nullptr)
  {
    return "";
  }
  if (SHA256(sha256_first.data(), SHA256_DIGEST_LENGTH, sha256_second.data()) == nullptr)
  {
    return "";
  }

  for (size_t i = 0; i < 4; i++)
  {
    ripemd160[1 + RIPEMD160_DIGEST_LENGTH + i] = sha256_second[i];
  }
  return encode_base58(ripemd160);
}

static std::mutex mtx;
void thread_class::operator()(const std::vector<std::string> &input_buffer, std::map<std::string, KeyCombination> &output_buffer,
  size_t from, size_t to, const std::string& pass_phrase, size_t child_keys_num) const
{
  BN_CTX_start(ctx);

  std::map<std::string, KeyCombination> private_version_buffer;
  for (size_t index = from; index < to; index++)
  {
    std::array<uint8_t, SHA512_DIGEST_LENGTH> seed_bytes;
    int result_PBKDF2 = generate_binary_seed(input_buffer[index], pass_phrase, seed_bytes);
    if (result_PBKDF2 != 1)
    {
      logger->error(std::string("PKCS5_PBKDF2_HMAC: ") + std::to_string(result_PBKDF2));
      return;
    }

    std::array<uint8_t, SHA512_DIGEST_LENGTH> I;
    uint8_t* result_hmac = generate_bitcoin_hmac_sha512(seed_bytes, I);
    if (result_hmac == nullptr)
    {
      logger->error(std::string("PKCS5_PBKDF2_HMAC: ") + std::to_string(result_PBKDF2));
      return;
    }

    std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)> master_secret_key;
    std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)> master_chain_code;

    std::copy(I.begin(), I.begin() + (SHA512_DIGEST_LENGTH >> 1u), master_secret_key.begin());
    std::copy(I.begin() + (SHA512_DIGEST_LENGTH >> 1u), I.end(), master_chain_code.begin());

    if (!is_key_good(master_secret_key))
    {
      logger->warn(input_buffer[index] + " produced incorrect master key");
      continue;
    }
    
    std::array<uint8_t, (SHA512_DIGEST_LENGTH >> 1u)> child_normal_key, child_chain_code;
    for (size_t i = 0; i < (SHA512_DIGEST_LENGTH >> 1u); i++)
    {
      child_normal_key[i] = master_secret_key[i];
      child_chain_code[i] = master_chain_code[i];
    }
    if (derive_child_key_private(group, ctx, child_normal_key, child_chain_code, child_normal_key, child_chain_code, 0x80000000 | 44) != 0)
    {
      logger->warn(input_buffer[index] + ": error derive_child_key_private");
      continue;
    }
    if (derive_child_key_private(group, ctx, child_normal_key, child_chain_code, child_normal_key, child_chain_code, 0x80000000 | 0) != 0)
    {
      logger->warn(input_buffer[index] + ": error derive_child_key_private");
      continue;
    }
    if (derive_child_key_private(group, ctx, child_normal_key, child_chain_code, child_normal_key, child_chain_code, 0x80000000 | 0) != 0)
    {
      logger->warn(input_buffer[index] + ": error derive_child_key_private");
      continue;
    }
    if (derive_child_key_private(group, ctx, child_normal_key, child_chain_code, child_normal_key, child_chain_code, 0) != 0)
    {
      logger->warn(input_buffer[index] + ": error derive_child_key_private");
      continue;
    }

    for (size_t i = 0; i < child_keys_num; i++)
    {
      KeyCombination combination;
      if (derive_child_key_private(group, ctx, child_normal_key, child_chain_code, combination.private_key, combination.chain_code, i) != 0)
      {
        logger->warn(input_buffer[index] + ": error derive_child_key_private");
        continue;
      }
      if ((combination.address = convert_private_key_to_address(group, ctx, combination.private_key, combination.public_key)).empty())
      {
        logger->warn(input_buffer[index] + ": error convert_private_key_to_address");
        continue;
      }

      private_version_buffer.insert(std::pair<std::string, KeyCombination>(input_buffer[index], combination));
    }
  }
  BN_CTX_end(ctx);

  mtx.lock();
  output_buffer.insert(private_version_buffer.begin(), private_version_buffer.end());
  mtx.unlock();
}
std::shared_ptr<spdlog::logger> thread_class::logger;
