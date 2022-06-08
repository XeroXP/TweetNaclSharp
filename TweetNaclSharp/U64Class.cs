namespace TweetNaclSharp
{
    internal class U64Class
    {
        public uint Hi { get; set; }
        public uint Lo { get; set; }

        public U64Class()
        {
            Hi = 0;
            Lo = 0;
        }

        public U64Class(uint hi, uint lo)
        {
            Hi = hi;
            Lo = lo;
        }

        public ulong ToUlong()
        {
            ulong x = Hi;
            x = (x << 32);
            x = x | Lo;
            return x;
        }

        public static U64Class ToU64Class(ulong x)
        {
            uint hi = (uint)(x >> 32);
            uint lo = (uint)(x & 0xffffffff);
            return new U64Class(hi, lo);
        }
    }
}
