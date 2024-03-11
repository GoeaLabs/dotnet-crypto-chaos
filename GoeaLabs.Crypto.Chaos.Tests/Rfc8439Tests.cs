using GoeaLabs.Crypto.Chaos.Internal;

namespace GoeaLabs.Crypto.Chaos.Tests;

[TestClass]
public class Rfc8439Tests
{
    [TestMethod]
    public void QuarterRound_should_satisfy_vectors_when_applied_on_state()
    {
        Span<uint> test = ChaosTestVectors.QuarterRound.Test;

        Rfc8439.QuarterRound(
            test,
            ChaosTestVectors.QuarterRound.A,
            ChaosTestVectors.QuarterRound.B,
            ChaosTestVectors.QuarterRound.C, 
            ChaosTestVectors.QuarterRound.D);

        Assert.IsTrue(test.SequenceEqual(ChaosTestVectors.QuarterRound.Pass));
    }

    [TestMethod]
    public void State_with_32_bit_counter_and_96_bit_nonce_should_satisfy_test_vectors()
    {
        Span<uint> next = stackalloc uint[Rfc8439.Sl];

        Rfc8439.OuterBlock(next, 
            ChaosTestVectors.OuterBlock.Kernel, 
            ChaosTestVectors.OuterBlock.Locale, 
            ChaosTestVectors.OuterBlock.Rounds);

        Assert.IsTrue(next.SequenceEqual(ChaosTestVectors.OuterBlock.Expect32));
    }
}