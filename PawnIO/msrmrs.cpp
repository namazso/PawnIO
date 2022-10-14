#include <array>
#include <cstdint>

// the msr and mrs instructions only allow immediates for selecting the architecture specific registers to act on so in
// order to provide arbitrary register access to the VM without metamorphism (which is disallowed by HVCI) we simply
// generate stubs for all possible registers into an array, and shove them into an executable section.  Note that this
// must be constexpr so that it can go into a read-only section because W^X is enforced
//
// arguments to (mrs|msr) instruction:
//
// [ 0: 4] <Xt> (x0 for us)
// [ 5: 7] op2
// [ 8:11] crm
// [12:15] crn
// [16:18] op1
// [19:19] op0
//
// so we need to iterate over all possible values in [5:19], meaning 0x8000 functions for both instruction

template <bool Mrs>
constexpr std::array<uint64_t, 0x8000> generate_msrmrs()
{
  constexpr auto mrs = 0xD5300000; // mrs x0, <reg>
  constexpr auto msr = 0xD5100000; // msr <reg>, x0

  constexpr auto ret = 0xD65F03C0;

  constexpr auto magic = (Mrs ? mrs : msr) | ((uint64_t)ret << 32);

  std::array<uint64_t, 0x8000> arr{};
  for (auto i = 0u; i < 0x8000; ++i)
    arr[i] = magic | (i << 5);
  return arr;
}

#pragma section (".msrmrs", read, execute)

__declspec(allocate(".msrmrs")) constexpr auto k_mrsfn = generate_msrmrs<true>();
__declspec(allocate(".msrmrs")) constexpr auto k_msrfn = generate_msrmrs<false>();

// convenience functions where you only need to pass the assembled instruction

unsigned arm_mrs(unsigned instruction)
{
  return ((uint32_t(*)())&k_mrsfn[(instruction >> 5) & 0x7FFF])();
}

void arm_msr(unsigned instruction, unsigned v)
{
  ((void(*)(uint32_t))&k_msrfn[(instruction >> 5) & 0x7FFF])(v);
}
