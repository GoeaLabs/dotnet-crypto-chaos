namespace GoeaLabs.Crypto.Chaos.Tests
{
    [TestClass]
    public class ChaosLocaleTests
    {
        [TestMethod]
        [DataRow(ulong.MaxValue, ulong.MaxValue, 1UL)]
        public void Mock_throws_when_stream_overflows(ulong pebble, ulong stream, ulong toMock)
        {
            var tested = new Exception();
            
            try
            {
                _ = new ChaosLocale(pebble, stream).Mock(toMock);
            }
            catch (Exception thrown)
            {
                tested = thrown;
            }
            
            Assert.IsTrue(
                tested.GetType() == typeof(ChaosException) && 
                ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrLocale && 
                ((ChaosException)tested).InnerException?.GetType() == typeof(OverflowException));
        }

        [TestMethod]
        // returns same
        [DataRow(0UL, 0UL, 0UL, 0UL, 0UL)]
        // needs 1 byte, consumes pebble (0, 0), sets future ChaosLocale to to (1, 0)
        [DataRow(0UL, 0UL, 1UL, 1UL, 0UL)]
        // needs 64 bytes (1 pebble), consumes pebble (ulong.MaxValue - 1, 0),
        // sets future ChaosLocale to (ulong.MaxValue, 0)
        [DataRow(ulong.MaxValue - 1UL, 0UL, 64UL, ulong.MaxValue, 0UL)]
        // needs 640 bytes (10 pebbles), consumes pebbles (ulong.MaxValue, 0) through (8, 1),
        // sets future ChaosLocale to (9, 1)
        [DataRow(ulong.MaxValue, 0UL, 64UL * 10UL, 9UL, 1UL)]
        public void Mock_behaves_correctly(
            ulong inPebble, ulong inStream, ulong nBytes, ulong okPebble, ulong okStream)
        {
            var locale = new ChaosLocale(inPebble, inStream);
            var passes = new ChaosLocale(okPebble, okStream);
            var tested = locale.Mock(nBytes);

            Assert.IsTrue(tested.Same(passes));
        }

        [TestMethod]
        [DataRow(ulong.MaxValue, ulong.MaxValue, 1UL)]
        public void Skip_throws_when_stream_overflows(ulong pebble, ulong stream, ulong toSkip)
        {
            var tested = new Exception();
            
            try
            {
                _ = new ChaosLocale(pebble, stream).Skip(toSkip);
            }
            catch (Exception thrown)
            {
                tested = thrown;
            }
            
            Assert.IsTrue(
                tested.GetType() == typeof(ChaosException) && 
                ((ChaosException)tested).ErrorCode == ChaosErrorCode.ErrLocale && 
                ((ChaosException)tested).InnerException?.GetType() == typeof(OverflowException));
            
        }

        [TestMethod]
        // returns same
        [DataRow(0UL, 0UL, 0UL, 0UL, 0UL)]
        // inPebble = 0, inStream = 0, pebbles = ulong.MaxValue, newPebble = ulong.MaxValue, newStream = 0
        [DataRow(0UL, 0UL, ulong.MaxValue, ulong.MaxValue, 0UL)]
        // inPebble = 1, inStream = 0, pebbles = ulong.MaxValue, newPebble = 0, newStream = 1
        [DataRow(1UL, 0UL, ulong.MaxValue, 0UL, 1UL)]
        public void Skip_behaves_correctly(
            ulong inPebble, ulong inStream, ulong pebbles, ulong okPebble, ulong okStream)
        {
            var passes = new ChaosLocale(okPebble, okStream);
            var tested = new ChaosLocale(inPebble, inStream).Skip(pebbles);
            
            Assert.IsTrue(tested.Same(passes));
        }

        [TestMethod]
        public void Same_behaves_correctly()
        {
            var locale = new ChaosLocale(0, 0);
            var passes = new ChaosLocale(0, 0);
            
            Assert.IsTrue(locale.Same(passes));
        }
    }
}
