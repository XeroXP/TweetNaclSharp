namespace TweetNaclSharp.Core.Extensions
{
    public static class ArrayExtensions
    {
        public static T[] SubArray<T>(this T[] array, int offset, int length = 0)
        {
            if (length <= 0) length = array.Length - offset;
            if (length <= 0) return Array.Empty<T>();
            T[] result = new T[length];
            Array.Copy(array, offset, result, 0, length);
            return result;
        }
    }
}
