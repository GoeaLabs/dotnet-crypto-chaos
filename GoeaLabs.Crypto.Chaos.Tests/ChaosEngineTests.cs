using System.Numerics;

namespace GoeaLabs.Crypto.Chaos.Tests;

[TestClass]
public class ChaosEngineTests
{
    private static uint[] Kernel => ChaosTestVectors.OuterBlock.Kernel;

    private static int Rounds => ChaosTestVectors.OuterBlock.Rounds;

    private static ulong Pebble => ChaosTestVectors.OuterBlock.Pebble;

    private static ulong Stream => ChaosTestVectors.OuterBlock.Stream;


    #region Internal methods tests
    
    [TestMethod]
    [DataRow(ChaosEngine.PebbleLen - 1)]
    [DataRow(ChaosEngine.PebbleLen + 1)]
    [ExpectedException(typeof(ArgumentException))]
    public void OuterBlock_UInt8_throws_ArgumentException_on_invalid_output_length(int length)
    {
        var locale = new ChaosLocale(Pebble, Stream);
        
        Span<byte> output = stackalloc byte[length];
        _ = ChaosEngine.OuterBlock(output, Kernel, Rounds, locale);
    }
    
    [TestMethod]
    [DataRow(ChaosEngine.PebbleLen64 - 1)]
    [DataRow(ChaosEngine.PebbleLen64 + 1)]
    [ExpectedException(typeof(ArgumentException))]
    public void OuterBlock_UInt64_throws_ArgumentException_on_invalid_output_length(int length)
    {
        var locale = new ChaosLocale(Pebble, Stream);
        
        Span<ulong> output = stackalloc ulong[length];
        _ = ChaosEngine.OuterBlock(output, Kernel, Rounds, locale);
    }

    [TestMethod]
    public void OuterBlock_UInt32_passes_test_vectors()
    {
        var locale = new ChaosLocale(Pebble, Stream);
        
        Span<uint> output = stackalloc uint[ChaosEngine.PebbleLen32];
        _ = ChaosEngine.OuterBlock(output,Kernel, Rounds, locale);

        Assert.IsTrue(output.SequenceEqual(ChaosTestVectors.OuterBlock.Expect32));
    }

    [TestMethod]
    public void OuterBlock_UInt8_passes_test_vectors()
    {
        var locale = new ChaosLocale(Pebble, Stream);
        
        Span<byte> output = stackalloc byte[ChaosEngine.PebbleLen];
        _ = ChaosEngine.OuterBlock(output, Kernel, Rounds, locale);

        Assert.IsTrue(output.SequenceEqual(ChaosTestVectors.OuterBlock.Expect8));
    }
    
    [TestMethod]
    public void OuterBlock_UInt64_passes_test_vectors()
    {
        var locale = new ChaosLocale(Pebble, Stream);
        
        Span<ulong> output = stackalloc ulong[ChaosEngine.PebbleLen64];
        _ = ChaosEngine.OuterBlock(output, Kernel, Rounds, locale);

        Assert.IsTrue(output.SequenceEqual(ChaosTestVectors.OuterBlock.Expect64));
    }
    
    #endregion
    
    #region Public methods tests

    [TestMethod]
    [DataRow(ChaosEngine.KernelLen + 1)]
    [DataRow(ChaosEngine.KernelLen - 1)]
    public void NewKernel_throws_on_invalid_output_length(int length)
    {
        var tested = new Exception(); 
        
        Span<uint> kernel = stackalloc uint[length];

        try
        {
            ChaosEngine.NewKernel(kernel);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(ChaosException) 
            && ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrKernel);
    }

    [TestMethod]
    [DataRow(ChaosEngine.KernelLen + 1)]
    [DataRow(ChaosEngine.KernelLen - 1)]
    public void Load_UInt8_throws_on_invalid_kernel_length(int length)
    {
        Span<uint> kernel = stackalloc uint[length];
        
        var output = Span<byte>.Empty;
        var locale = new ChaosLocale();
        var tested = new Exception();

        try
        {
            _ = ChaosEngine.Load(output, kernel, Rounds, locale);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(ChaosException) 
            && ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrKernel);
    }

    [TestMethod]
    [DataRow(ChaosEngine.DefRounds + 1)]
    [DataRow(ChaosEngine.DefRounds - 1)]
    public void Load_UInt8_throws_on_invalid_number_of_rounds(int rounds)
    {
        var locale = new ChaosLocale();
        var output = Span<byte>.Empty;

        var tested = new Exception();

        try
        {
            _ = ChaosEngine.Load(output, Kernel, rounds, locale);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(ChaosException) 
            && ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrRounds);
        
    }

    [TestMethod]
    [DataRow(ChaosEngine.KernelLen + 1)]
    [DataRow(ChaosEngine.KernelLen - 1)]
    public void Load_Int64_throws_on_invalid_kernel_length(int length)
    {
        const long minVal = long.MinValue;
        const long maxVal = long.MaxValue;
        
        Span<uint> kernel = stackalloc uint[length];
        
        var locale = new ChaosLocale();
        var output = Span<long>.Empty;
        var tested = new Exception();

        try
        {
            _ = ChaosEngine.Load(output, minVal, maxVal, kernel, Rounds, locale);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(ChaosException) 
            && ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrKernel);
    }

    [TestMethod]
    [DataRow(ChaosEngine.DefRounds + 1)]
    [DataRow(ChaosEngine.DefRounds - 1)]
    public void Load_Int64_throws_on_invalid_number_of_rounds(int rounds)
    {
        const long minVal = long.MinValue;
        const long maxVal = long.MaxValue;
        
        var locale = new ChaosLocale();
        var output = Span<long>.Empty;
        var tested = new Exception();

        try
        {
            _ = ChaosEngine.Load(output, minVal, maxVal, Kernel, rounds, locale);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(ChaosException) 
            && ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrRounds);
    }
    
    [TestMethod]
    [DataRow(-8, -7)]
    [DataRow(7, 8)]
    public void Load_Int64_throws_if_interval_has_less_than_2_numbers(
        long minVal, long maxVal)
    {
        var locale = new ChaosLocale();
        var output = Span<long>.Empty;
        var tested = new Exception();

        try
        {
            _ = ChaosEngine.Load(output, minVal, maxVal, Kernel, Rounds, locale);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(ChaosException) 
            && ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrMinMax);
    }
    
    [TestMethod]
    [DataRow(sbyte.MinValue, sbyte.MaxValue, 1000)]
    [DataRow(short.MinValue, short.MaxValue, 1000)]
    [DataRow(int.MinValue, int.MaxValue, 1000)]
    [DataRow(long.MinValue, long.MaxValue, 1000)]
    public void Load_Int64_behaves_correctly(long minVal, long maxVal, int length)
    {
        var locale = new ChaosLocale();
        
        Span<long> output = stackalloc long[length];
        _ = ChaosEngine.Load(output, minVal, maxVal, Kernel, Rounds, locale);

        var passes = true;
        
        foreach (var number in output)
        {
            if (number >= minVal && number < maxVal)
                continue;

            passes = false;
            break;
        }
        
        Assert.IsTrue(passes);
    }

    [TestMethod]
    [DataRow(ChaosEngine.KernelLen + 1)]
    [DataRow(ChaosEngine.KernelLen - 1)]
    public void Load_BigInteger_throws_on_invalid_kernel_length(int length)
    {
        var minVal = ChaosEngine.BigIntMin;
        var maxVal = ChaosEngine.BigIntMax;
        
        Span<uint> kernel = new uint[length];
        
        var locale = new ChaosLocale();
        var output = Span<BigInteger>.Empty;
        var tested = new Exception();
        
        try
        {
            _ = ChaosEngine.Load(output, minVal, maxVal, kernel, Rounds, locale);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(ChaosException) 
            && ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrKernel);
    }

    [TestMethod]
    [DataRow(ChaosEngine.DefRounds + 1)]
    [DataRow(ChaosEngine.DefRounds - 1)]
    public void Load_BigInteger_throws_on_invalid_number_of_rounds(int rounds)
    {
        var minVal = ChaosEngine.BigIntMin;
        var maxVal = ChaosEngine.BigIntMax;
        
        var locale = new ChaosLocale();
        var output = Span<BigInteger>.Empty;
        var tested = new Exception();

        try
        {
            _ = ChaosEngine.Load(output, minVal, maxVal, Kernel, rounds, locale);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(ChaosException) 
            && ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrRounds);
    }
    
    [TestMethod]
    [DataRow("minVal")]
    [DataRow("maxVal")]
    public void Load_BigInteger_throws_if_minVal_or_maxVal_is_outside_of_512_bit_range(string which)
    {
        var minVal = which == "minVal" 
            ? ChaosEngine.BigIntMin - BigInteger.One 
            : ChaosEngine.BigIntMin;
        
        var maxVal = which == "minVal" 
            ? ChaosEngine.BigIntMax 
            : ChaosEngine.BigIntMax + BigInteger.One;
        
        var locale = new ChaosLocale();
        var output = Span<BigInteger>.Empty;
        var tested = new Exception();

        try
        {
            _ = ChaosEngine.Load(output, minVal, maxVal, Kernel, Rounds, locale);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(ChaosException) 
            && ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrBitLen);
    }
    

    [TestMethod]
    [DataRow(-8, -7)]
    [DataRow(7, 8)]
    public void Load_BigInteger_throws_if_interval_has_less_than_2_numbers(
        long minVal, long maxVal)
    {
        var locale = new ChaosLocale();
        var output = Span<BigInteger>.Empty;
        var tested = new Exception();

        try
        {
            ChaosEngine.Load(output, minVal, maxVal, Kernel, Rounds, locale);
        }
        catch (Exception thrown)
        {
            tested = thrown;
        }
        
        Assert.IsTrue(
            tested.GetType() == typeof(ChaosException) 
            && ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrMinMax);
    }
    
    [TestMethod]
    [DataRow(sbyte.MinValue, sbyte.MaxValue, 1000)]
    [DataRow(short.MinValue, short.MaxValue, 1000)]
    [DataRow(int.MinValue, int.MaxValue, 1000)]
    [DataRow(long.MinValue, long.MaxValue, 1000)]
    public void Load_BigInteger_behaves_correctly_for_8bit_to_64bit_intervals(long minVal, long maxVal, int length)
    {
        var locale = new ChaosLocale();
        
        var output = new BigInteger[length];
        ChaosEngine.Load(output, minVal, maxVal, Kernel, Rounds, locale);

        var passes = true;
        // ReSharper disable once LoopCanBeConvertedToQuery
        foreach (var number in output)
        {
            if (number >= minVal && number < maxVal)
                continue;

            passes = false;
            break;
        }
        
        Assert.IsTrue(passes);
    }

    [TestMethod]
    [DataRow(1000)]
    public void Load_BigInteger_behaves_correctly_for_128bit_intervals(int length)
    {
        var locale = new ChaosLocale();
        
        var minVal = Int128.MinValue;
        var maxVal = Int128.MaxValue;
        
        var output = new BigInteger[length];
        _ = ChaosEngine.Load(output, minVal, maxVal, Kernel, Rounds, locale);
        
        var passes = true;
        // ReSharper disable once LoopCanBeConvertedToQuery
        foreach (var number in output)
        {
            if (number >= minVal && number < maxVal) 
                continue;

            passes = false;
            break;
        }
        
        Assert.IsTrue(passes);
    }

    [TestMethod]
    [DataRow(1000)]
    public void Load_BigInteger_behaves_correctly_for_128bit_to_512bit_intervals(int length)
    {
        var locale = new ChaosLocale();
        
        var minVal = Int128.MaxValue;
        var maxVal = ChaosEngine.BigIntMax;
        
        var output = new BigInteger[length];
        _ = ChaosEngine.Load(output, minVal, maxVal, Kernel, Rounds, locale);
        
        var passes = true;
        // ReSharper disable once LoopCanBeConvertedToQuery
        foreach (var number in output)
        {
            if (number >= minVal && number < maxVal) 
                continue;

            passes = false;
            break;
        }
        
        Assert.IsTrue(passes);
    }
    
    #endregion
}