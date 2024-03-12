# CHAOS

![GitHub](https://img.shields.io/github/license/goealabs/dotnet-crypto-chaos?style=for-the-badge)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/goealabs/dotnet-crypto-chaos?include_prereleases&style=for-the-badge)
![Nuget (with prereleases)](https://img.shields.io/nuget/vpre/GoeaLabs.Crypto.Chaos?style=for-the-badge)

# Project Description

- A cryptographically secure deterministic random number generator (**CSDRNG**) for .NET6+, based on **RFC8439 ChaCha**.
- **Chaos** and **ChaCha** are algorithmically indistinguishable, but Chaos includes additional features that make it 
distinct enough to merit a separate name.
- To provide clarity and facilitate comparison, a table is often the best approach:

| **ChaCha**                                                          | **Chaos**                                                                  |
|---------------------------------------------------------------------|----------------------------------------------------------------------------|
| Uses 1 ```UInt32``` as block counter and 3 ```UInt32``` as *nonce*. | Uses 1 ```UInt64``` as block counter and 1 ```UInt64``` as stream counter. |
| Hardcoded to 20 rounds.                                             | Customizable number of rounds.                                             |
| Does not have a standard coordinate system.                         | Has a standard coordinate system allowing for arbitrary location jumps.    | 
| Produces bytes only.                                                | Capable of advanced random number generation.                              |

# Technical Summary

For any given **kernel** (seed), **Chaos** is capable of producing 2<sup>64</sup> **streams**, each stream containing
2<sup>64</sup> **pebbles**, each **pebble** being composed of 2<sup>4</sup> ```UInt32```(s), for a grand total of 
2<sup>134</sup> ```Byte```(s).

# Library Features

- Apache 2.0 license;
- Passes **RFC8439** test vectors;
- Endian-neutral;
- Can produce random numbers up to 512 bits with scaling to arbitrary ranges;
- No memory allocations beyond BigInteger overload;
- Supports all .NET platforms, including WebAssembly;
- No unsafe code;
- Fully managed;
- Simple API;

## Examples

````csharp
using System.Numerics;
using GoeaLabs.Crypto.Chaos;

#region Setup

// Use a well known kernel
Span<uint> kernel = stackalloc uint[]
{
    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c
};

// Alternatively, generate a new random kernel

// Span<uint> kernel = stackalloc uint[ChaosEngine.KernelLen];
// ChaosEngine.NewKernel(kernel);

// Default number of rounds (20)
const int rounds = ChaosEngine.DefRounds;

// New default locale (starts at Pebble = 0, Stream = 0)
var locale = new ChaosLocale();

// Buffer size for future use
const int length = 10;

#endregion

#region Random byte generation

Console.WriteLine(" === RANDOM BYTE GENERATION === \n");

// Generate cryptographically secure random bytes with custom kernel and rounds
Span<byte> buffer = stackalloc byte[length];
locale = ChaosEngine.Load(buffer, kernel, rounds, locale);

// Or simply let Chaos handle kernel generation and rounds internally

//ChaosEngine.Load(buffer);

Console.WriteLine($"Pebble as UInt8 array:\n[{string.Join(", ", buffer.ToArray())}]\n");
Console.WriteLine($"Locale is now: {locale.ToString()}\n");

#endregion

#region Random number generation

Console.WriteLine(" === RANDOM NUMBER GENERATION === \n");

// Up to now we've been using stream 0. Let's use stream 1 for random number generation
locale = new ChaosLocale(0, 1);
Console.WriteLine($"Locale set to: {locale.ToString()}\n");

// Generate cryptographically secure die rolls
const int minVal = 1;
const int maxVal = 7; // maxVal is exclusive

Span<long> rolled = stackalloc long[length];
locale = ChaosEngine.Load(rolled, minVal, maxVal, kernel, rounds, locale);

// Or simply let Chaos handle kernel generation and rounds internally

//ChaosEngine.Load(rolled, minVal, maxVal);

Console.WriteLine($"Die rolls:\n[{string.Join(", ", rolled.ToArray())}]\n");
Console.WriteLine($"Locale is now: {locale.ToString()}\n");

// Produce cryptographically secure 512 bit signed BigIntegers (maximum supported bit length)
var min512 = ChaosEngine.BigIntMin;
var max512 = ChaosEngine.BigIntMax;

var box512 = new BigInteger[length];
locale = ChaosEngine.Load(box512, min512, max512, kernel, rounds, locale);

// Or simply let Chaos handle kernel generation and rounds internally

//ChaosEngine.Load(box512, minVal, maxVal);

Console.WriteLine($"512 bit BigInteger array:\n[{string.Join(", ", box512.ToArray())}]\n");
Console.WriteLine($"Locale is now: {locale.ToString()}\n");

// Produce cryptographically secure 128 bit signed BigIntegers
var min128 = -BigInteger.One << 127;
var max128 = (BigInteger.One << 127) - 1;

var box128 = new BigInteger[length];
locale = ChaosEngine.Load(box128, min128, max128, kernel, rounds, locale);

// Or simply let Chaos handle kernel generation and rounds internally

//ChaosEngine.Load(box128, minVal, maxVal);

Console.WriteLine($"128 bit BigInteger array:\n[{string.Join(", ", box128.ToArray())}]\n");
Console.WriteLine($"Locale is now: {locale.ToString()}\n");

// Produce cryptographically secure 103 bit signed BigIntegers
var min103 = -BigInteger.One << 102;
var max103 = (BigInteger.One << 102) - 1;

var box103 = new BigInteger[10];
locale = ChaosEngine.Load(box103, min103, max103, kernel, rounds, locale);

// Or simply let Chaos handle kernel generation and rounds internally

//ChaosEngine.Load(box128, minVal, maxVal);

Console.WriteLine($"103 bit BigInteger signed array:\n[{string.Join(", ", box103.ToArray())}]\n");
Console.WriteLine($"Locale is now: {locale.ToString()}\n");

#endregion

#region Operations on ChaosLocale

Console.WriteLine(" === LOCALE OPERATIONS === \n");

// Assume we are at the very end of stream 2
// ( Pebble = ulong.MaxValue, Stream = 2 )
locale = new ChaosLocale(ulong.MaxValue, 2);

Console.WriteLine($"Locale is now: {locale.ToString()}\n");

// Simulate the new coordinates we can resume work from, provided the
// current locale is used to produce 100 BYTES
var simLoc = locale.Mock(100);

Console.WriteLine($"Locale Mock(100) simulation: {simLoc.ToString()}\n");

// Advance the locale by skipping 100 PEBBLES
var newLoc = simLoc.Skip(100);

Console.WriteLine($"Locale Skip(100) simulation: {newLoc.ToString()}\n");

#endregion
````

## Installation

Install with NuGet Package Manager Console
```
Install-Package GoeaLabs.Chaos
```

Install with .NET CLI
```
dotnet add package GoeaLabs.Chaos
```
