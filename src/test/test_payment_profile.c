/* See LICENSE for licensing information. */
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/payment/payment_profile.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "test/test.h"
#include "core/crypto/onion_crypto.h"
#include "trunnel/extension.h"

/* Public synthetic fixtures copied from
 * eltord/spec/vectors/payment_renewal_v1.json; no real ntor/wallet secrets.
 * Both independently bound hops and their two chained allocations are used. */
static const struct {
  const char *seed, *client, *server, *context, *binding;
  const char *request_key, *reply_key;
  const char *terms, *terms_digest, *initial_ids, *initial_digest;
  const char *requests[2], *replies[2], *request_digests[2], *allocations[2];
} fixtures[] = {
  {
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "7075626c69632073796e746865746963206e746f722d763320636c69656e7420484441"
    "544120686f702031",
    "7075626c69632073796e746865746963206e746f722d76332073657276657220484441"
    "544120686f702031",
    "d075ad31c80df2eb63b423d17c7396896e9216db7ac6d09f89164b1b71459fc7",
    "e9da6b9638a83a386624d0aa6e7fe7ffc788297581362c4603d3acbe02a9a3c9",
    "b9e9f2f37f45f955112f81e8bdc34afe5c793c5ee37e02be5f480719d012568b",
    "7e0f56dea0bd266dfc4b0f0d682557509cacb7ae68e8edaa87575728db049950",
    "01010a00000000000003e80000ea600000ea6000003a98000000000000000000000000"
    "05265c0000000090000000000000000000007530",
    "aa81021a97a0002d71070a961b41c6d91e8e47cce8d1b409498b39b1513e0ab8",
    "b0b328971c2c7363b810b8f370db0330e9aeaf12cf99634a4eccf3e7a827fdfb9ad961"
    "4181bd471924628106ca049425c70c2eb2e897299b6362c7ff4ea0299c2749e0737b16"
    "1b83b57e0ab6ca9c9b4f8507306051f0d59aa6af25d0128fae1d638e9ed25de938f24b"
    "c255df84736e2382b1655caeb46302d656bdc3bc99ee182bcbd032bd6e5d82f248ca74"
    "fccb1ffd19d6c2d77d9ba48862e6a88941c6af660527430669bcbebc6c0702f16877b5"
    "c916e49bd38d5d92821c3eb6adc1c5529cdb8cb5a628495b0fd83d81be8ab40f68b116"
    "c221b058cdbf77c64cafca8b86e0e463015711c5a3f71db6115a1addcdf6d42f94da67"
    "814b2e720428d09d71a719f3ba40a0f9ad169ef5de3041d3e296259afc28500dc2e917"
    "e956cb215332da2312c71179945675e717d747d76752e9890ddc642f4b771331ae991f"
    "826684ec17",
    "f380b5b496c342912165f9db7ac7f79965642a5ef293dedb053233259a975f63",
    {
    "01000000000000000001000000000000000b0a804b5074d76b74fc1567792f909c69ad"
    "00000000000927c00000ea60aa81021a97a0002d71070a961b41c6d91e8e47cce8d1b4"
    "09498b39b1513e0ab8f380b5b496c342912165f9db7ac7f79965642a5ef293dedb0532"
    "33259a975f631618b18e4a0276af2bdb9ede65fc94b77d5a92a5fe500babe7d3aa660f"
    "f66c231137d1b0191ed65f3b0ee3af51750e63a1d7bf17eacfeb485545e4389de69caa"
    "2c96bb62ca036fe1027a7af599e8620d2b0bcce753e2b592ba270760d505ed5671acb2"
    "399f923e92d029126af3c3a508ee9d1a68c210e4a69589a98479771cf3c02c63ff1df8"
    "840053281707265de05313ef766cb87d1ff434137b887f5e131307726a22d0b66493a0"
    "956091638e73f127eb22145c33ad081237b465528a52095607795cb0929ba2602df4b1"
    "55cdf25608adeb60dfb1e9b16fdc2e7ff6dfa742a105d46fccff930d950a71ab300620"
    "8a34ce91cf990d275b368a3ceca55ed708a80366b65153f8c2816abb2489e1276ad200"
    "1612ff898bbecfb1b98051549e18ba48a4570aac705e4b936a180d06842612ac286922"
    "a6be79ab53d8ae36d4be337b1234a2a124457cc866505630addc804c0d9e4cf7811299"
    "55414f83848fc2ee",
    "0100000000000000000200000000000000150ae386b83227337a4f49eea98b7447ed73"
    "0000000000124f800000ea60aa81021a97a0002d71070a961b41c6d91e8e47cce8d1b4"
    "09498b39b1513e0ab80d3ee1bba972a2c851b10d8897585808c44260f1623e833cdb65"
    "8349fc8c109e97488030f6ce1b6d4c4c93292dff0239bf20000c5f65fcf72a696e57db"
    "8138af0e996fcdb2c49fa5db0b20c395a384f01b4e169585e2d1743a84fa0544283602"
    "44dd9219ea1ea2b5209f7930f7d5b0f249e057e53dbb43e9e52b521b42dc179fb532f0"
    "9dc2acdb44d4837249c42cc707ca9690b4217c06a970a9e83532efaf6013e3e8d9d0ae"
    "b648c1e2254362e48686955ca9b904cde038f48979c83c87da794ee2bc98106b76fa68"
    "cd31f9d161af649d930447f15e577eee00ad0e1a68cc10a041a2a16384c5298af7ac63"
    "8f37ab9f91711b489cceda0b3105f7b4083c5ac5b4e472a49e5a93144b593aa2f2c6ab"
    "9a10ce721556f30ecf9f652b469d8fb10659b70aec0802a8fdee7e77aed2d14968fd75"
    "03113573855afd07e1ea4d3a94d3d49b8689a3a0a61bbd9e5874612490ff51c8ac68ad"
    "2b6e8b5a5302df003947d3876169d756ad232130fe9cb1a37c333ba469be51e8037d41"
    "3672120f92ee5d0c"
    },
    {
    "010000000000000000000001804b5074d76b74fc1567792f909c69adb99977e246f3e3"
    "d485855d19555008e53913ae8f723d30cb6b10a9327b54af760d3ee1bba972a2c851b1"
    "0d8897585808c44260f1623e833cdb658349fc8c109e0000000000057ebb0000000000"
    "0927c00000000000083d60aa81021a97a0002d71070a961b41c6d91e8e47cce8d1b409"
    "498b39b1513e0ab8000000000000000b0a000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000f9589858036edf58f8b939efe38c8cf1db3e10085f67fd28"
    "acb8664eb9989168",
    "010000000000000000000002e386b83227337a4f49eea98b7447ed739e536bc0067970"
    "53222c23ec5b577f6094fb676f7a5d4cabaf09aee50c63cc1c7afd0d18325b4d2ae8d6"
    "1ae0203aeb4b5d24bab63156e8ef636b695e551b37fc00000000000ea67b0000000000"
    "124f800000000000116520aa81021a97a0002d71070a961b41c6d91e8e47cce8d1b409"
    "498b39b1513e0ab800000000000000150a000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000065c347e7b37a6b7650ae304b283126cc90c15b21ff063f5"
    "714ed48f18479070"
    },
    {
    "b99977e246f3e3d485855d19555008e53913ae8f723d30cb6b10a9327b54af76",
    "9e536bc006797053222c23ec5b577f6094fb676f7a5d4cabaf09aee50c63cc1c"
    },
    {
    "0d3ee1bba972a2c851b10d8897585808c44260f1623e833cdb658349fc8c109e",
    "7afd0d18325b4d2ae8d61ae0203aeb4b5d24bab63156e8ef636b695e551b37fc"
    },
  },
  {
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "7075626c69632073796e746865746963206e746f722d763320636c69656e7420484441"
    "544120686f702032",
    "7075626c69632073796e746865746963206e746f722d76332073657276657220484441"
    "544120686f702032",
    "7e8bcf40d3c7b3b627ce37a639a4433b664a76dec8ef434e246a6ac034f7a45b",
    "c0f24315c74ab8da386ed415b17864d612ba06980f3a5b74725f9074a03f3202",
    "1e30f8192735e48645e4d17e8d20d5bd4e063eba93cae4f8973af7fcb9755aba",
    "97603d3075a52bd7417810f4f2ec0738993d62c7197b0c1d487386f417680a3b",
    "01010a00000000000007d00000ea600000ea6000003a98000000000000000000000000"
    "05265c0000000090000000000000000000007530",
    "ecebeffb49624124ac92c36621f6ad2f8bba382f902e29c1e50647f61131cfa2",
    "5878d70cb36e8f626f7828c4994a448fb1bd4fdbfbfcbd22defe2dca7c595310524cb8"
    "76149240578b527da8d8620b33f062283b8870d4cdee3c208e629eca1bd3e724644e65"
    "9b35af0ff2395eebce97d3e612d55f49a933e494100d62fac5a7e69d1dfc232b96dc4e"
    "d0ef2e01c5934ca4363759ce33dfba7011444c34b965ff35fd675ddc9911653a79bd84"
    "854505af218352504160bc1c4256e73d26e35f7ea8d9a4c81578e200e37f578be166ff"
    "4f1647fc02b51fe65a9334811406a6b026b54ef945f44d3b75d4e25a5a261139b062ac"
    "442eac8670d3e9f26fef31af31e6bf687771aa7ead79305a4b1a8dc28823084623d775"
    "b535fc0e4214127a3be7ba5ce7257668f5846c8aa7f34712e5a5ea26821f18b4fe1471"
    "9f54a5cec6e79b6acae8d27e7289fa3a78f210cde43a2a5acec3f4e8fa4a749ef820a3"
    "bf415c15a0",
    "e5756db1a354f740bdecc6e410b8de5ce789887936d4c21a6cba5dd1b3c036fc",
    {
    "01000000000000000001000000000000000b0abf8f912e3ffb1652318a9256e6335903"
    "00000000000927c00000ea60ecebeffb49624124ac92c36621f6ad2f8bba382f902e29"
    "c1e50647f61131cfa2e5756db1a354f740bdecc6e410b8de5ce789887936d4c21a6cba"
    "5dd1b3c036fc48641ab5f7d1c88627ea88c0ce118ccc142ecef307fb2620772933d0cd"
    "fff8ed440a2217b6d6ca501b9844afb6f66fbd06fe751f70b125ab1ec4a7d9b67b9ac2"
    "1a2fc051d23fe0c5195c9bca4282b0ec15a84309bd96c193cc2436732fb4fcbc35389f"
    "7bc4f585b6558496c713459521751fc4d067a8c9144004367ec3894683e2ab309c501e"
    "25e441067ba307a2c74387a2795f2b6bfea0752a20ae03f98f00c1c45b23ce370a76ae"
    "085023a276289223eca706b8a8080cfb2aa776f89450840aaab6ac8446d8c7f0238240"
    "44b588968da404001173e88e1211337f0117256eed75a60751ef64c73888fe7cd18aec"
    "2d51cdb7a35fd4749df00cdd79aba431fb454454cc686d5232940c0706e5ed238c8a94"
    "d1b280ebce8766d9dba92923e3f9c875ed823918473cfe3ba39b34f9d79d0c45d26d03"
    "d733c8a45138c1487bf5dc1804365f214490a10fb1b2c622ae42d9cc50ddb7cc954b24"
    "9218026cb271b93d",
    "0100000000000000000200000000000000150a5c550df4884f91874feaea1e783ee1b0"
    "0000000000124f800000ea60ecebeffb49624124ac92c36621f6ad2f8bba382f902e29"
    "c1e50647f61131cfa2a3f802571c9fae7760fcc4cb5e9095fa8670a3e66387ad89c5ec"
    "6997aa06db45348dacb79fc994d48f2fb4c26de1c619687b4569bcaa70056a866cbc27"
    "b75bffa80174a99a8ded867d9e4bd632a0e913ce73b26b83a8b2c3d77f287b058b68f0"
    "979dd9d4f61dbf3a1c0f0d4906b0900f536c072138f4080aa175800a74f6e89f0afdb8"
    "f8852f05c421bc88ae470275186014a5cb8ee535096def5a74ccb41e97b537859e7977"
    "84f3cb46bfbec58fcea22a36428eb482ec87698f6ecc5853c11785481deb124406324a"
    "ac440a3ed214b136d432bdfb4e9d9963e3f9837b61baf0c3c337d0dd301a2b01f9b1a0"
    "f292f0cd7d744cd847cd8d0a0ec69a96e66a8828b57c0031e01f4d59096991cd1b3a95"
    "6c6282b9786a4afbff773c3ed92f4bdf33f52af31eaec6804930275278152cb428adc9"
    "9623b8c2a3ec754aa786f62c9acc33e6cbf687c3d391f7587821cacc8a270087940bb4"
    "4c599fc4824dea10aa8f3996140ab05b356c2955f7eed07524fd83f7a613bfe4a6258e"
    "bbccf3125313ee2a"
    },
    {
    "010000000000000000000001bf8f912e3ffb1652318a9256e63359034b57a856de6e56"
    "496a647f3e8c435494332ccc43e0cf839a1c14ff77f4ec66fca3f802571c9fae7760fc"
    "c4cb5e9095fa8670a3e66387ad89c5ec6997aa06db450000000000057ebb0000000000"
    "0927c00000000000083d60ecebeffb49624124ac92c36621f6ad2f8bba382f902e29c1"
    "e50647f61131cfa2000000000000000b0a000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000001f900eb0b01da00366f3f140f1001761f8a441e4724f45cb"
    "d7d2c108530b6e9d",
    "0100000000000000000000025c550df4884f91874feaea1e783ee1b00e8ce34bc9a4d3"
    "8dda685092f1306f8c647acf7fb3702dc0c750391e3a0a225cf38daa1b6f9afe2d98e5"
    "ba6ec30f72c78dde2ae867e057bb466c32c3f29de82400000000000ea67b0000000000"
    "124f800000000000116520ecebeffb49624124ac92c36621f6ad2f8bba382f902e29c1"
    "e50647f61131cfa200000000000000150a000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000a371daf7c4a1f6ac92fcdaf32d48c7dae83008ff65c23b3e"
    "f96f28d86c84df50"
    },
    {
    "4b57a856de6e56496a647f3e8c435494332ccc43e0cf839a1c14ff77f4ec66fc",
    "0e8ce34bc9a4d38dda685092f1306f8c647acf7fb3702dc0c750391e3a0a225c"
    },
    {
    "a3f802571c9fae7760fcc4cb5e9095fa8670a3e66387ad89c5ec6997aa06db45",
    "f38daa1b6f9afe2d98e5ba6ec30f72c78dde2ae867e057bb466c32c3f29de824"
    },
  },
};

/* Initial-profile fixtures from payment_profile_initial_vectors.py.
 * Reproduce/check with the generator; these are independent of the C codec. */
static const char *initial_fixtures[] = {
    "0100000102030405060708090a0b0c0d0e0f01010a00000000000003e80000ea600000"
    "ea6000003a9800000000000000000000000005265c0000000090000000000000000000"
    "007530f380b5b496c342912165f9db7ac7f79965642a5ef293dedb053233259a975f63"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000059edf4c9b1f206214215607646d741cb2f16d03b7a4aa0ed"
    "c036b087cdd5d299",
    "0100000102030405060708090a0b0c0d0e0fcdf75ab6519798f197571e7bbcdc68f6ec"
    "29af86ab9aeb8daf3bb315ba319492aa81021a97a0002d71070a961b41c6d91e8e47cc"
    "e8d1b409498b39b1513e0ab8f380b5b496c342912165f9db7ac7f79965642a5ef293de"
    "db053233259a975f63000061a800000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000008186687de92ab3c2b11a8a62bb523eaeeddff1df51a46d07"
    "c8c5105450cbc484",
    "0100000102030405060708090a0b0c0d0e0faa81021a97a0002d71070a961b41c6d91e"
    "8e47cce8d1b409498b39b1513e0ab8f380b5b496c342912165f9db7ac7f79965642a5e"
    "f293dedb053233259a975f630000000000000001000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000dbb2ce4415b01e0dfc04090aee1300d78a5e2cfb67f66c07"
    "5d074f6a86d7ca04",
    "0103000102030405060708090a0b0c0d0e0f12a953d1efecaa493c759fb337527471ec"
    "d3242e689162832b8d00bf913e710aaa81021a97a0002d71070a961b41c6d91e8e47cc"
    "e8d1b409498b39b1513e0ab8f380b5b496c342912165f9db7ac7f79965642a5ef293de"
    "db053233259a975f630000000000000002000000000000eadb0000e9e50001247d0000"
    "0000000000000000000700000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000bfb69eb577e4c616eebd4a0a199a80566ffb6229f42ceae3"
    "3c9fa6fc52131f4c"
};

static int
unhex(uint8_t *out, size_t size, const char *hex)
{
  return base16_decode((char *)out, size, hex, strlen(hex));
}

/* Independent MAC construction allows authenticated malformed fields,
 * rather than accidentally testing only a MAC failure. */
static void
resign(uint8_t wire[463], unsigned command, const uint8_t key[32],
       const uint8_t binding[32])
{
  const char *domain = command == 224 ?
    "eltor/payment-renew/v1/request-mac" : command == 225 ?
    "eltor/payment-renew/v1/reply-mac" : "eltor/payment-start/v1/mac";
  uint8_t msg[600];
  size_t n = strlen(domain);
  msg[0] = 0; msg[1] = (uint8_t)n;
  memcpy(msg+2, domain, n);
  memcpy(msg+2+n, binding, 32);
  msg[34+n] = (uint8_t)command;
  memcpy(msg+35+n, wire, 431);
  crypto_hmac_sha256((char *)wire+431, (const char *)key, 32,
                     (const char *)msg, n+466);
}

static void
test_payment_profile_vectors(void *arg)
{
  (void)arg;
  payment_profile_keys_t keys = {0};
  payment_profile_policy_t policy;
  payment_profile_message_t m;
  uint8_t seed[32], client[128], server[128], terms[55], ids[10][32];
  uint8_t wire[463], encoded[463], digest[32], parent[32], q[32];
  uint8_t expected[32];
  for (size_t i = 0; i < ARRAY_LENGTH(fixtures); ++i) {
    tt_int_op(unhex(seed, 32, fixtures[i].seed), OP_EQ, 32);
    int cl = unhex(client, sizeof(client), fixtures[i].client);
    int sl = unhex(server, sizeof(server), fixtures[i].server);
    tt_int_op(cl, OP_GT, 0); tt_int_op(sl, OP_GT, 0);
    tt_int_op(payment_profile_derive_keys(&keys, seed, client, cl, server, sl),
              OP_EQ, PAYMENT_PROFILE_OK);
#define KEY_CHECK(field, fixture) \
    tt_int_op(unhex(expected, 32, fixtures[i].fixture), OP_EQ, 32); \
    tt_mem_op(keys.field, OP_EQ, expected, 32)
    KEY_CHECK(context, context);
    KEY_CHECK(binding, binding);
    KEY_CHECK(renew_request, request_key);
    KEY_CHECK(renew_reply, reply_key);
#undef KEY_CHECK
    tt_int_op(unhex(terms, 55, fixtures[i].terms), OP_EQ, 55);
    tt_int_op(payment_profile_policy_decode(&policy, terms, 55), OP_EQ, 0);
    uint8_t terms_out[55];
    tt_int_op(payment_profile_policy_encode(terms_out, 55, &policy), OP_EQ, 0);
    tt_mem_op(terms_out, OP_EQ, terms, 55);
    tt_int_op(unhex(q, 32, fixtures[i].terms_digest), OP_EQ, 32);
    tt_int_op(payment_profile_terms_digest(digest, &policy), OP_EQ, 0);
    tt_mem_op(digest, OP_EQ, q, 32);
    tt_int_op(unhex((uint8_t *)ids, 320, fixtures[i].initial_ids), OP_EQ, 320);
    tt_int_op(payment_profile_initial_digest(digest, keys.binding, q, ids),
              OP_EQ, 0);
    tt_int_op(unhex(parent, 32, fixtures[i].initial_digest), OP_EQ, 32);
    tt_mem_op(digest, OP_EQ, parent, 32);
    for (size_t p = 0; p < 2; ++p) {
      tt_int_op(unhex(wire, 463, fixtures[i].requests[p]), OP_EQ, 463);
      tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_RENEW, wire, 463,
                                       keys.renew_request, keys.binding),
                OP_EQ, 0);
      tt_u64_op(m.u.renew.period, OP_EQ, p+1);
      tt_int_op(payment_profile_renew_check(&m.u.renew, &policy,
                                            p+1, q, parent),
                OP_EQ, 0);
      tt_int_op(payment_profile_encode(encoded, 463, &m, keys.renew_request,
                                       keys.binding), OP_EQ, 0);
      tt_mem_op(encoded, OP_EQ, wire, 463);
      tt_int_op(payment_profile_request_digest(digest, PAYMENT_PROFILE_RENEW,
                                               wire, 463), OP_EQ, 0);
      tt_int_op(unhex(expected, 32, fixtures[i].request_digests[p]),
                OP_EQ, 32);
      tt_mem_op(digest, OP_EQ, expected, 32);
      tt_int_op(payment_profile_allocation_digest(digest, keys.binding,
                                                  wire, 463), OP_EQ, 0);
      tt_int_op(unhex(parent, 32, fixtures[i].allocations[p]), OP_EQ, 32);
      tt_mem_op(digest, OP_EQ, parent, 32);
      tt_int_op(unhex(wire, 463, fixtures[i].replies[p]), OP_EQ, 463);
      tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_RENEWED, wire, 463,
                                       keys.renew_reply, keys.binding),
                OP_EQ, 0);
      tt_mem_op(m.u.renewed.allocation, OP_EQ, parent, 32);
      tt_int_op(payment_profile_encode(encoded, 463, &m, keys.renew_reply,
                                       keys.binding), OP_EQ, 0);
      tt_mem_op(encoded, OP_EQ, wire, 463);
    }
    payment_profile_keys_clear(&keys);
    uint8_t zero_keys[sizeof(keys)];
    memset(zero_keys, 0, sizeof(zero_keys));
    tt_mem_op(&keys, OP_EQ, zero_keys, sizeof(keys));
  }
 done:
  payment_profile_keys_clear(&keys);
}

static void
test_payment_profile_rejections(void *arg)
{
  (void)arg;
  uint8_t wire[464], key[32], binding[32], q[32], parent[32];
  payment_profile_message_t m;
  payment_profile_policy_t policy;
  uint8_t terms[55];
  tt_int_op(unhex(key, 32, fixtures[0].request_key), OP_EQ, 32);
  tt_int_op(unhex(binding, 32, fixtures[0].binding), OP_EQ, 32);
  tt_int_op(unhex(q, 32, fixtures[0].terms_digest), OP_EQ, 32);
  tt_int_op(unhex(parent, 32, fixtures[0].initial_digest), OP_EQ, 32);
  tt_int_op(unhex(terms, 55, fixtures[0].terms), OP_EQ, 55);
  tt_int_op(payment_profile_policy_decode(&policy, terms, 55), OP_EQ, 0);
#define RESET() \
  tt_int_op(unhex(wire, sizeof(wire), fixtures[0].requests[0]), OP_EQ, 463)
#define DECODE(result) \
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_RENEW, wire, 463, \
                                   key, binding), OP_EQ, result)
  RESET();
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_RENEW, wire, 462,
                                   key, binding), OP_EQ,
            PAYMENT_PROFILE_ERR_LENGTH);
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_RENEW, wire, 464,
                                   key, binding), OP_EQ,
            PAYMENT_PROFILE_ERR_LENGTH);
  wire[462] ^= 1; DECODE(PAYMENT_PROFILE_ERR_MAC);
  RESET(); wire[0] = 2; resign(wire, 224, key, binding);
  DECODE(PAYMENT_PROFILE_ERR_HEADER);
  RESET(); wire[1] = 1; resign(wire, 224, key, binding);
  DECODE(PAYMENT_PROFILE_ERR_HEADER);
  RESET(); wire[18] = 9; resign(wire, 224, key, binding);
  DECODE(PAYMENT_PROFILE_ERR_HEADER);
  RESET(); memset(wire+2, 255, 8); resign(wire, 224, key, binding);
  DECODE(PAYMENT_PROFILE_ERR_SEQUENCE);
  RESET(); wire[17] ^= 1; resign(wire, 224, key, binding);
  DECODE(PAYMENT_PROFILE_ERR_SEQUENCE);
  RESET(); wire[42] ^= 1; resign(wire, 224, key, binding);
  DECODE(PAYMENT_PROFILE_ERR_SEQUENCE);
  RESET(); wire[46] ^= 1; resign(wire, 224, key, binding);
  DECODE(PAYMENT_PROFILE_ERR_SEQUENCE);
  RESET(); memset(wire+111, 0, 32); resign(wire, 224, key, binding);
  DECODE(PAYMENT_PROFILE_ERR_SEQUENCE);
  RESET(); memcpy(wire+143, wire+111, 32); resign(wire, 224, key, binding);
  DECODE(PAYMENT_PROFILE_ERR_SEQUENCE);
  RESET(); DECODE(0);
  tt_int_op(payment_profile_renew_check(&m.u.renew, &policy, 2, q, parent),
            OP_EQ, PAYMENT_PROFILE_ERR_SEQUENCE);
  m.u.renew.terms[0] ^= 1;
  tt_int_op(payment_profile_renew_check(&m.u.renew, &policy, 1, q, parent),
            OP_EQ, PAYMENT_PROFILE_ERR_TERMS);
  m.u.renew.terms[0] ^= 1; m.u.renew.parent[0] ^= 1;
  tt_int_op(payment_profile_renew_check(&m.u.renew, &policy, 1, q, parent),
            OP_EQ, PAYMENT_PROFILE_ERR_PARENT);
  m.u.renew.parent[0] ^= 1;
  policy.max_age_ms = 1199999;
  tt_int_op(payment_profile_renew_check(&m.u.renew, &policy, 1, q, parent),
            OP_EQ, PAYMENT_PROFILE_ERR_POLICY);
  policy.max_age_ms = 1200000;
  tt_int_op(payment_profile_renew_check(&m.u.renew, &policy, 1, q, parent),
            OP_EQ, 0);
  policy.max_periods = 2;
  m.u.renew.period = 2; m.u.renew.first_round = 21;
  m.u.renew.activation_ms = 1200000;
  tt_int_op(payment_profile_renew_check(&m.u.renew, &policy, 2, q, parent),
            OP_EQ, PAYMENT_PROFILE_ERR_POLICY);
  RESET(); binding[0] ^= 1; DECODE(PAYMENT_PROFILE_ERR_MAC);
  binding[0] ^= 1;
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_RENEWED, wire, 463,
                                   key, binding), OP_EQ,
            PAYMENT_PROFILE_ERR_MAC);
  tt_int_op(payment_profile_decode(&m, (payment_profile_command_t)230,
                                   wire, 463, key, binding), OP_EQ,
            PAYMENT_PROFILE_ERR_HEADER);
#undef RESET
#undef DECODE
 done:
  ;
}

static void
test_payment_profile_replies(void *arg)
{
  (void)arg;
  uint8_t wire[463], key[32], binding[32];
  payment_profile_message_t m;
  tt_int_op(unhex(key, 32, fixtures[0].reply_key), OP_EQ, 32);
  tt_int_op(unhex(binding, 32, fixtures[0].binding), OP_EQ, 32);
#define RESET_REPLY() \
  tt_int_op(unhex(wire, 463, fixtures[0].replies[0]), OP_EQ, 463)
#define REPLY_DECODE(result) \
  resign(wire, 225, key, binding); \
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_RENEWED, wire, 463, \
                                   key, binding), OP_EQ, result)
  RESET_REPLY(); wire[3] = 1; REPLY_DECODE(PAYMENT_PROFILE_ERR_HEADER);
  RESET_REPLY(); wire[157] = 1; REPLY_DECODE(PAYMENT_PROFILE_ERR_HEADER);
  RESET_REPLY(); wire[430] = 1; REPLY_DECODE(PAYMENT_PROFILE_ERR_HEADER);
  RESET_REPLY(); wire[2] = 10; REPLY_DECODE(PAYMENT_PROFILE_ERR_BODY);
  RESET_REPLY(); wire[2] = 1; REPLY_DECODE(PAYMENT_PROFILE_ERR_BODY);
  RESET_REPLY(); wire[2] = 8; REPLY_DECODE(PAYMENT_PROFILE_ERR_BODY);
  memset(wire+60, 0, 32); REPLY_DECODE(0);
  RESET_REPLY(); wire[155] ^= 1; REPLY_DECODE(PAYMENT_PROFILE_ERR_BODY);
  RESET_REPLY(); wire[115] ^= 1; REPLY_DECODE(PAYMENT_PROFILE_ERR_BODY);
  /* BAD_SEQUENCE can safely report overflowing request arithmetic. */
  RESET_REPLY(); wire[2] = 7;
  memset(wire+4, 255, 8); memset(wire+60, 0, 32);
  memset(wire+100, 0, 16); REPLY_DECODE(0);
  /* A failure leaves no partial message or old successful result. */
  memset(&m, 0xff, sizeof(m));
  wire[462] ^= 1;
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_RENEWED, wire, 463,
                                   key, binding), OP_EQ,
            PAYMENT_PROFILE_ERR_MAC);
  uint8_t zero[sizeof(m)];
  memset(zero, 0, sizeof(zero));
  tt_mem_op(&m, OP_EQ, zero, sizeof(m));
#undef RESET_REPLY
#undef REPLY_DECODE
 done:
  ;
}

static void
test_payment_profile_policy(void *arg)
{
  (void)arg;
  payment_profile_policy_t p;
  payment_profile_policy_t empty = {0};
  char text[112];
  uint8_t terms[56], encoded[55];
  tt_int_op(payment_profile_policy_parse_hex(&p, fixtures[0].terms), OP_EQ, 0);
  tt_int_op(payment_profile_policy_encode(encoded, sizeof(encoded), &p),
            OP_EQ, 0);
  tt_int_op(unhex(terms, sizeof(terms), fixtures[0].terms), OP_EQ, 55);
  tt_mem_op(encoded, OP_EQ, terms, 55);
  tor_snprintf(text, sizeof(text), "%s0", fixtures[0].terms);
  tt_int_op(payment_profile_policy_parse_hex(&p, text), OP_EQ,
            PAYMENT_PROFILE_ERR_LENGTH);
  tt_mem_op(&p, OP_EQ, &empty, sizeof(p));
  memcpy(text, fixtures[0].terms, 111);
  text[0] = 'A';
  tt_int_op(payment_profile_policy_parse_hex(&p, text), OP_EQ,
            PAYMENT_PROFILE_ERR_BODY);
  tt_mem_op(&p, OP_EQ, &empty, sizeof(p));
  text[0] = ' ';
  tt_int_op(payment_profile_policy_parse_hex(&p, text), OP_EQ,
            PAYMENT_PROFILE_ERR_BODY);
  tt_int_op(payment_profile_policy_parse_hex(&p, NULL), OP_EQ,
            PAYMENT_PROFILE_ERR_LENGTH);
  tt_int_op(unhex(terms, sizeof(terms), fixtures[0].terms), OP_EQ, 55);
  tt_int_op(payment_profile_policy_decode(&p, terms, 54), OP_EQ,
            PAYMENT_PROFILE_ERR_LENGTH);
  tt_int_op(payment_profile_policy_decode(&p, terms, 56), OP_EQ,
            PAYMENT_PROFILE_ERR_LENGTH);
  static const unsigned offsets[] = {0, 1, 2, 11, 15};
  for (size_t i = 0; i < ARRAY_LENGTH(offsets); ++i) {
    terms[offsets[i]] ^= 1;
    tt_int_op(payment_profile_policy_decode(&p, terms, 55), OP_EQ,
              PAYMENT_PROFILE_ERR_POLICY);
    terms[offsets[i]] ^= 1;
  }
  tt_int_op(payment_profile_policy_decode(&p, terms, 55), OP_EQ, 0);
  p.grace_ms = 60001;
  tt_int_op(payment_profile_policy_encode(encoded, 55, &p), OP_EQ,
            PAYMENT_PROFILE_ERR_POLICY);
  p.grace_ms = 0; p.rate_msat = 0; p.initial_handshake_fee_msat = 0;
  p.paid_quota_bytes = 0;
  tt_int_op(payment_profile_policy_encode(encoded, 55, &p), OP_EQ, 0);
  p.max_age_ms = 0;
  tt_int_op(payment_profile_policy_encode(encoded, 55, &p), OP_EQ,
            PAYMENT_PROFILE_ERR_POLICY);
  p.max_age_ms = UINT64_MAX; p.max_periods = 1;
  tt_int_op(payment_profile_policy_encode(encoded, 55, &p), OP_EQ,
            PAYMENT_PROFILE_ERR_POLICY);
  p.max_periods = UINT32_MAX; p.setup_timeout_ms = 0;
  tt_int_op(payment_profile_policy_encode(encoded, 55, &p), OP_EQ,
            PAYMENT_PROFILE_ERR_POLICY);
  p.setup_timeout_ms = UINT32_MAX; p.rate_msat = UINT64_MAX;
  p.initial_handshake_fee_msat = UINT64_MAX; p.paid_quota_bytes = UINT64_MAX;
  p.grace_ms = 60000;
  tt_int_op(payment_profile_policy_encode(encoded, 55, &p), OP_EQ, 0);
  tt_int_op(payment_profile_policy_decode(&p, encoded, 55), OP_EQ, 0);
  tt_u64_op(p.rate_msat, OP_EQ, UINT64_MAX);
 done:
  ;
}

static void
test_payment_profile_initial(void *arg)
{
  (void)arg;
  payment_profile_keys_t keys = {0};
  uint8_t seed[32], client[128], server[128], wire[463], encoded[463];
  payment_profile_message_t m;
  tt_int_op(unhex(seed, 32, fixtures[0].seed), OP_EQ, 32);
  int cl = unhex(client, sizeof(client), fixtures[0].client);
  int sl = unhex(server, sizeof(server), fixtures[0].server);
  tt_int_op(payment_profile_derive_keys(&keys, seed, client, cl, server, sl),
            OP_EQ, 0);
  static const unsigned reserved[] = {105, 118, 90, 150};
  for (unsigned i = 0; i < 4; ++i) {
    payment_profile_command_t command = (payment_profile_command_t)(226+i);
    const uint8_t *key = i % 2 ? keys.start_reply : keys.start_request;
    tt_int_op(unhex(wire, sizeof(wire), initial_fixtures[i]), OP_EQ, 463);
    tt_int_op(payment_profile_decode(&m, command, wire, 463,
                                     key, keys.binding),
              OP_EQ, 0);
    tt_int_op(payment_profile_encode(encoded, 463, &m, key, keys.binding),
              OP_EQ, 0);
    tt_mem_op(encoded, OP_EQ, wire, 463);
    wire[reserved[i]] = 1; resign(wire, command, key, keys.binding);
    tt_int_op(payment_profile_decode(&m, command, wire, 463,
                                     key, keys.binding),
              OP_EQ, PAYMENT_PROFILE_ERR_HEADER);
  }
  /* QUERY round zero is distinct from START round one. */
  tt_int_op(unhex(wire, sizeof(wire), initial_fixtures[2]), OP_EQ, 463);
  wire[1] = 1; resign(wire, 228, keys.start_request, keys.binding);
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_START_STATUS, wire, 463,
                                   keys.start_request, keys.binding), OP_EQ,
            PAYMENT_PROFILE_ERR_BODY);
  wire[89] = 0; resign(wire, 228, keys.start_request, keys.binding);
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_START_STATUS, wire, 463,
                                   keys.start_request, keys.binding),
            OP_EQ, 0);
  /* A refusal cannot retain a successful commitment. */
  tt_int_op(unhex(wire, sizeof(wire), initial_fixtures[1]), OP_EQ, 463);
  wire[1] = 1; resign(wire, 227, keys.start_reply, keys.binding);
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_COMMITTED, wire, 463,
                                   keys.start_reply, keys.binding), OP_EQ,
            PAYMENT_PROFILE_ERR_BODY);
  memset(wire+50, 0, 64); resign(wire, 227, keys.start_reply, keys.binding);
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_COMMITTED, wire, 463,
                                   keys.start_reply, keys.binding), OP_EQ, 0);
  /* ACTIVE clocks must agree with the boundary, never grant a new minute. */
  tt_int_op(unhex(wire, sizeof(wire), initial_fixtures[3]), OP_EQ, 463);
  wire[129] ^= 1; resign(wire, 229, keys.start_reply, keys.binding);
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_STARTED_STATUS, wire,
                                   463, keys.start_reply, keys.binding), OP_EQ,
            PAYMENT_PROFILE_ERR_BODY);
  tt_int_op(unhex(wire, sizeof(wire), initial_fixtures[3]), OP_EQ, 463);
  wire[1] = 5; resign(wire, 229, keys.start_reply, keys.binding);
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_STARTED_STATUS, wire,
                                   463, keys.start_reply, keys.binding), OP_EQ,
            PAYMENT_PROFILE_ERR_BODY);
  memset(wire+130, 0, 12); resign(wire, 229, keys.start_reply, keys.binding);
  tt_int_op(payment_profile_decode(&m, PAYMENT_PROFILE_STARTED_STATUS, wire,
                                   463, keys.start_reply, keys.binding),
            OP_EQ, 0);
  /* max_age=65000 can terminate ACTIVE round two before its nominal end. */
  m.u.started.state = 3;
  m.u.started.round = 2;
  m.u.started.elapsed_ms = 61000;
  m.u.started.round_remaining_ms = 59000;
  m.u.started.enforcement_remaining_ms = 4000;
  tt_int_op(payment_profile_encode(wire,463,&m,keys.start_reply,keys.binding),OP_EQ,0);
  tt_int_op(payment_profile_decode(&m,PAYMENT_PROFILE_STARTED_STATUS,wire,463,
                                   keys.start_reply,keys.binding),OP_EQ,0);
  m.u.started.enforcement_remaining_ms = 119001;
  tt_int_op(payment_profile_encode(wire,463,&m,keys.start_reply,keys.binding),OP_EQ,
            PAYMENT_PROFILE_ERR_BODY);
 done:
  payment_profile_keys_clear(&keys);
}

static void
test_payment_profile_export_lifetime(void *arg)
{
  (void)arg;
  payment_profile_export_t result = {0}, zero = {0};
  payment_profile_keys_t *keys = NULL;
  memset(&result.keys, 0x5a, sizeof(result.keys));
  result.valid = true;
  tt_int_op(payment_profile_export_take(&keys, &result, false), OP_EQ, -1);
  tt_ptr_op(keys, OP_EQ, NULL);
  tt_mem_op(&result, OP_EQ, &zero, sizeof(zero));
  tt_int_op(payment_profile_export_take(&keys, &result, false), OP_EQ, 0);
  tt_ptr_op(keys, OP_EQ, NULL);
  tt_int_op(payment_profile_export_take(&keys, &result, true), OP_EQ, -1);
  memset(&result.keys, 0x5a, sizeof(result.keys));
  result.valid = true;
  tt_int_op(payment_profile_export_take(&keys, &result, true), OP_EQ, 0);
  tt_assert(keys);
  tt_int_op(keys->renew_request[0], OP_EQ, 0x5a);
  tt_mem_op(&result, OP_EQ, &zero, sizeof(zero));
  memset(&result.keys, 0x6b, sizeof(result.keys));
  result.valid = true;
  tt_int_op(payment_profile_export_take(&keys, &result, true), OP_EQ, -1);
  tt_int_op(keys->renew_request[0], OP_EQ, 0x5a);
  tt_mem_op(&result, OP_EQ, &zero, sizeof(zero));
  payment_profile_keys_free(keys);
  tt_ptr_op(keys, OP_EQ, NULL);
 done:
  payment_profile_export_clear(&result);
  payment_profile_keys_free(keys);
}

static void
test_payment_profile_capabilities(void *arg)
{
  uint8_t terms[55], expected[55];
  const char *start[] = {"1", "226", "227", "228", "229", fixtures[0].terms};
  const char *renew[] = {"1", "224", "225", fixtures[0].terms};
  const char *free_cap[] = {"1", "2", "128", "600000"};
  const char *future[] = {"2", "future"};
  (void)arg;
  tt_int_op(base16_decode((char *)expected,55,fixtures[0].terms,110), OP_EQ,55);
  tt_int_op(payment_profile_parse_capability(terms,PAYMENT_CAPABILITY_START,6,start),OP_EQ,1);
  tt_mem_op(terms,OP_EQ,expected,55);
  tt_int_op(payment_profile_parse_capability(terms,PAYMENT_CAPABILITY_RENEW,4,renew),OP_EQ,1);
  tt_mem_op(terms,OP_EQ,expected,55);
  tt_int_op(payment_profile_parse_capability(terms,PAYMENT_CAPABILITY_FREE,4,free_cap),OP_EQ,1);
  tt_int_op(payment_profile_parse_capability(terms,PAYMENT_CAPABILITY_START,2,future),OP_EQ,0);
  tt_assert(fast_mem_is_zero((char *)terms,55));
  start[1] = "0226";
  tt_int_op(payment_profile_parse_capability(terms,PAYMENT_CAPABILITY_START,6,start),OP_EQ,-1);
  start[1] = "226";
  start[0] = "01";
  tt_int_op(payment_profile_parse_capability(terms,PAYMENT_CAPABILITY_START,6,start),OP_EQ,-1);
  start[0] = "1";
  start[5] = "00";
  tt_int_op(payment_profile_parse_capability(terms,PAYMENT_CAPABILITY_START,6,start),OP_EQ,-1);
  tt_int_op(payment_profile_parse_capability(terms,PAYMENT_CAPABILITY_RENEW,3,renew),OP_EQ,-1);
  free_cap[2] = "129";
  tt_int_op(payment_profile_parse_capability(terms,PAYMENT_CAPABILITY_FREE,4,free_cap),OP_EQ,-1);
 done: ;
}

static void
test_payment_profile_resource_extension(void *arg)
{
  const uint8_t expected[] = {1, 224, 2, 1, 1};
  const uint8_t duplicate[] = {2, 224, 2, 1, 1, 224, 2, 1, 1};
  uint8_t encoded[16], malformed[5];
  trn_extension_t *ext = trn_extension_new();
  (void)arg;
  tt_int_op(eltor_resource_extension_parse(ext), OP_EQ, 0);
  tt_int_op(eltor_resource_extension_add(ext), OP_EQ, 0);
  tt_int_op(eltor_resource_extension_add(ext), OP_EQ, -1);
  tt_int_op(trn_extension_encode(encoded, sizeof(encoded), ext), OP_EQ, 5);
  tt_mem_op(encoded, OP_EQ, expected, sizeof(expected));
  tt_int_op(eltor_resource_extension_parse(ext), OP_EQ, 1);
  trn_extension_free(ext); ext = NULL;
  tt_int_op(trn_extension_parse(&ext, duplicate, sizeof(duplicate)), OP_EQ, 9);
  tt_int_op(eltor_resource_extension_parse(ext), OP_EQ, -1);
  trn_extension_free(ext); ext = NULL;
  for (unsigned offset = 3; offset <= 4; ++offset) {
    memcpy(malformed, expected, sizeof(expected)); malformed[offset] = 2;
    tt_int_op(trn_extension_parse(&ext, malformed, sizeof(malformed)), OP_EQ, 5);
    tt_int_op(eltor_resource_extension_parse(ext), OP_EQ, -1);
    trn_extension_free(ext); ext = NULL;
  }
  memcpy(malformed, expected, sizeof(expected)); malformed[2] = 1;
  tt_int_op(trn_extension_parse(&ext, malformed, 4), OP_EQ, 4);
  tt_int_op(eltor_resource_extension_parse(ext), OP_EQ, -1);
 done:
  trn_extension_free(ext);
}

#define PROFILE_TEST(name) \
  { #name, test_payment_profile_##name, 0, NULL, NULL }
struct testcase_t payment_profile_tests[] = {
  PROFILE_TEST(vectors),
  PROFILE_TEST(rejections),
  PROFILE_TEST(replies),
  PROFILE_TEST(policy),
  PROFILE_TEST(initial),
  PROFILE_TEST(export_lifetime),
  PROFILE_TEST(capabilities),
  PROFILE_TEST(resource_extension),
  END_OF_TESTCASES
};
