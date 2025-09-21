using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Collections.Specialized;
using System.IO;
using System.IO.Compression;
using System.Net.Sockets;
using WebSocketSharp.Net;
using WebSocketSharp.Net.WebSockets;
using System.Collections;
using System.Threading;
using System.Net.Security;
using System.Diagnostics;
using System.Security.Cryptography;

namespace WebSocketSharp
{
    // Specifies the byte order.
    public enum ByteOrder
    {
        // Specifies Little-endian.
        Little,
        // Specifies Big-endian.
        Big
    }
    //=========================================================================================
    //========================================================================================
    /// <summary>
    /// Indicates the status code for the WebSocket connection close.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///   The values of this enumeration are defined in
    ///   <see href="http://tools.ietf.org/html/rfc6455#section-7.4">
    ///   Section 7.4</see> of RFC 6455.
    ///   </para>
    ///   <para>
    ///   "Reserved value" cannot be sent as a status code in
    ///   closing handshake by an endpoint.
    ///   </para>
    /// </remarks>
    public enum CloseStatusCode : ushort
    {
        /// <summary>
        /// Equivalent to close status 1000. Indicates normal close.
        /// </summary>
        Normal = 1000,
        /// <summary>
        /// Equivalent to close status 1001. Indicates that an endpoint is
        /// going away.
        /// </summary>
        Away = 1001,
        /// <summary>
        /// Equivalent to close status 1002. Indicates that an endpoint is
        /// terminating the connection due to a protocol error.
        /// </summary>
        ProtocolError = 1002,
        /// <summary>
        /// Equivalent to close status 1003. Indicates that an endpoint is
        /// terminating the connection because it has received a type of
        /// data that it cannot accept.
        /// </summary>
        UnsupportedData = 1003,
        /// <summary>
        /// Equivalent to close status 1004. Still undefined. A Reserved value.
        /// </summary>
        Undefined = 1004,
        /// <summary>
        /// Equivalent to close status 1005. Indicates that no status code was
        /// actually present. A Reserved value.
        /// </summary>
        NoStatus = 1005,
        /// <summary>
        /// Equivalent to close status 1006. Indicates that the connection was
        /// closed abnormally. A Reserved value.
        /// </summary>
        Abnormal = 1006,
        /// <summary>
        /// Equivalent to close status 1007. Indicates that an endpoint is
        /// terminating the connection because it has received a message that
        /// contains data that is not consistent with the type of the message.
        /// </summary>
        InvalidData = 1007,
        /// <summary>
        /// Equivalent to close status 1008. Indicates that an endpoint is
        /// terminating the connection because it has received a message that
        /// violates its policy.
        /// </summary>
        PolicyViolation = 1008,
        /// <summary>
        /// Equivalent to close status 1009. Indicates that an endpoint is
        /// terminating the connection because it has received a message that
        /// is too big to process.
        /// </summary>
        TooBig = 1009,
        /// <summary>
        /// Equivalent to close status 1010. Indicates that a client is
        /// terminating the connection because it has expected the server to
        /// negotiate one or more extension, but the server did not return
        /// them in the handshake response.
        /// </summary>
        MandatoryExtension = 1010,
        /// <summary>
        /// Equivalent to close status 1011. Indicates that a server is
        /// terminating the connection because it has encountered an unexpected
        /// condition that prevented it from fulfilling the request.
        /// </summary>
        ServerError = 1011,
        /// <summary>
        /// Equivalent to close status 1015. Indicates that the connection was
        /// closed due to a failure to perform a TLS handshake. A Reserved value.
        /// </summary>
        TlsHandshakeFailure = 1015
    }
    //=====================================================================================
    /// <summary>
    /// Specifies the method for compression.
    /// </summary>
    /// <remarks>
    /// The methods are defined in
    /// <see href="https://tools.ietf.org/html/rfc7692">
    /// Compression Extensions for WebSocket</see>.
    /// </remarks>
    public enum CompressionMethod : byte
    {
        /// <summary>
        /// Specifies no compression.
        /// </summary>
        None,
        /// <summary>
        /// Specifies DEFLATE.
        /// </summary>
        Deflate
    }
    //=====================================================================================
    /// <summary>
    /// Represents the event data for the <see cref="WebSocket.OnError"/> event.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///   The error event occurs when the <see cref="WebSocket"/> interface
    ///   gets an error.
    ///   </para>
    ///   <para>
    ///   If you would like to get the error message, you should access
    ///   the <see cref="ErrorEventArgs.Message"/> property.
    ///   </para>
    ///   <para>
    ///   If the error is due to an exception, you can get it by accessing
    ///   the <see cref="ErrorEventArgs.Exception"/> property.
    ///   </para>
    /// </remarks>
    public class ErrorEventArgs : EventArgs
    {
        private Exception _exception;
        private string _message;

        internal ErrorEventArgs(string message)
          : this(message, null)
        {
        }

        internal ErrorEventArgs(string message, Exception exception)
        {
            _message = message;
            _exception = exception;
        }

        /// <summary>
        /// Gets the exception that caused the error.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="System.Exception"/> instance that represents
        ///   the cause of the error.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not present.
        ///   </para>
        /// </value>
        public Exception Exception
        {
            get
            {
                return _exception;
            }
        }

        /// <summary>
        /// Gets the error message.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the error message.
        /// </value>
        public string Message
        {
            get
            {
                return _message;
            }
        }
    }
    //=====================================================================================
    /// <summary>
    /// Provides a set of static methods for websocket-sharp.
    /// </summary>
    public static class Ext
    {
        private static readonly byte[] _last = new byte[] { 0x00 };
        private static readonly int _maxRetry = 5;
        private const string _tspecials = "()<>@,;:\\\"/[]?={} \t";

        private static byte[] compress(this byte[] data)
        {
            if (data.LongLength == 0)
                return data;

            using (var input = new MemoryStream(data))
                return input.compressToArray();
        }

        private static MemoryStream compress(this Stream stream)
        {
            var ret = new MemoryStream();

            if (stream.Length == 0)
                return ret;

            stream.Position = 0;

            var mode = CompressionMode.Compress;

            using (var ds = new DeflateStream(ret, mode, true))
            {
                stream.CopyTo(ds, 1024);
                ds.Close(); // BFINAL set to 1.
                ret.Write(_last, 0, 1);

                ret.Position = 0;

                return ret;
            }
        }

        private static byte[] compressToArray(this Stream stream)
        {
            using (var output = stream.compress())
            {
                output.Close();

                return output.ToArray();
            }
        }

        private static byte[] decompress(this byte[] data)
        {
            if (data.LongLength == 0)
                return data;

            using (var input = new MemoryStream(data))
                return input.decompressToArray();
        }

        private static MemoryStream decompress(this Stream stream)
        {
            var ret = new MemoryStream();

            if (stream.Length == 0)
                return ret;

            stream.Position = 0;

            var mode = CompressionMode.Decompress;

            using (var ds = new DeflateStream(stream, mode, true))
            {
                ds.CopyTo(ret, 1024);

                ret.Position = 0;

                return ret;
            }
        }

        private static byte[] decompressToArray(this Stream stream)
        {
            using (var output = stream.decompress())
            {
                output.Close();

                return output.ToArray();
            }
        }

        private static bool isPredefinedScheme(this string value)
        {
            var c = value[0];

            if (c == 'h')
                return value == "http" || value == "https";

            if (c == 'w')
                return value == "ws" || value == "wss";

            if (c == 'f')
                return value == "file" || value == "ftp";

            if (c == 'g')
                return value == "gopher";

            if (c == 'm')
                return value == "mailto";

            if (c == 'n')
            {
                c = value[1];

                return c == 'e'
                       ? value == "news" || value == "net.pipe" || value == "net.tcp"
                       : value == "nntp";
            }

            return false;
        }

        internal static byte[] Append(this ushort code, string reason)
        {
            var codeAsBytes = code.ToByteArray(ByteOrder.Big);

            if (reason == null || reason.Length == 0)
                return codeAsBytes;

            var buff = new List<byte>(codeAsBytes);
            var reasonAsBytes = Encoding.UTF8.GetBytes(reason);

            buff.AddRange(reasonAsBytes);

            return buff.ToArray();
        }

        internal static byte[] Compress(
          this byte[] data,
          CompressionMethod method
        )
        {
            return method == CompressionMethod.Deflate ? data.compress() : data;
        }

        internal static Stream Compress(
          this Stream stream,
          CompressionMethod method
        )
        {
            return method == CompressionMethod.Deflate ? stream.compress() : stream;
        }

        internal static bool Contains(this string value, params char[] anyOf)
        {
            return anyOf != null && anyOf.Length > 0
                   ? value.IndexOfAny(anyOf) > -1
                   : false;
        }

        internal static bool Contains(
          this NameValueCollection collection,
          string name
        )
        {
            return collection[name] != null;
        }

        internal static bool Contains(
          this NameValueCollection collection,
          string name,
          string value,
          StringComparison comparisonTypeForValue
        )
        {
            var val = collection[name];

            if (val == null)
                return false;

            foreach (var elm in val.Split(','))
            {
                if (elm.Trim().Equals(value, comparisonTypeForValue))
                    return true;
            }

            return false;
        }

        internal static bool Contains<T>(
          this IEnumerable<T> source,
          Func<T, bool> condition
        )
        {
            foreach (T elm in source)
            {
                if (condition(elm))
                    return true;
            }

            return false;
        }

        internal static bool ContainsTwice(this string[] values)
        {
            var len = values.Length;
            var end = len - 1;

            Func<int, bool> seek = null;
            seek = idx => {
                if (idx == end)
                    return false;

                var val = values[idx];

                for (var i = idx + 1; i < len; i++)
                {
                    if (values[i] == val)
                        return true;
                }

                return seek(++idx);
            };

            return seek(0);
        }

        internal static T[] Copy<T>(this T[] sourceArray, int length)
        {
            var dest = new T[length];

            Array.Copy(sourceArray, 0, dest, 0, length);

            return dest;
        }

        internal static T[] Copy<T>(this T[] sourceArray, long length)
        {
            var dest = new T[length];

            Array.Copy(sourceArray, 0, dest, 0, length);

            return dest;
        }

        internal static void CopyTo(
          this Stream sourceStream,
          Stream destinationStream,
          int bufferLength
        )
        {
            var buff = new byte[bufferLength];

            while (true)
            {
                var nread = sourceStream.Read(buff, 0, bufferLength);

                if (nread <= 0)
                    break;

                destinationStream.Write(buff, 0, nread);
            }
        }

        internal static void CopyToAsync(
          this Stream sourceStream,
          Stream destinationStream,
          int bufferLength,
          Action completed,
          Action<Exception> error
        )
        {
            var buff = new byte[bufferLength];

            AsyncCallback callback = null;
            callback =
              ar => {
                  try
                  {
                      var nread = sourceStream.EndRead(ar);

                      if (nread <= 0)
                      {
                          if (completed != null)
                              completed();

                          return;
                      }

                      destinationStream.Write(buff, 0, nread);

                      sourceStream.BeginRead(buff, 0, bufferLength, callback, null);
                  }
                  catch (Exception ex)
                  {
                      if (error != null)
                          error(ex);
                  }
              };

            try
            {
                sourceStream.BeginRead(buff, 0, bufferLength, callback, null);
            }
            catch (Exception ex)
            {
                if (error != null)
                    error(ex);
            }
        }

        internal static byte[] Decompress(
          this byte[] data,
          CompressionMethod method
        )
        {
            return method == CompressionMethod.Deflate ? data.decompress() : data;
        }

        internal static Stream Decompress(
          this Stream stream,
          CompressionMethod method
        )
        {
            return method == CompressionMethod.Deflate
                   ? stream.decompress()
                   : stream;
        }

        internal static byte[] DecompressToArray(
          this Stream stream,
          CompressionMethod method
        )
        {
            return method == CompressionMethod.Deflate
                   ? stream.decompressToArray()
                   : stream.ToByteArray();
        }

        internal static void Emit(
          this EventHandler eventHandler,
          object sender,
          EventArgs e
        )
        {
            if (eventHandler == null)
                return;

            eventHandler(sender, e);
        }

        internal static void Emit<TEventArgs>(
          this EventHandler<TEventArgs> eventHandler,
          object sender,
          TEventArgs e
        )
          where TEventArgs : EventArgs
        {
            if (eventHandler == null)
                return;

            eventHandler(sender, e);
        }

        internal static string GetAbsolutePath(this Uri uri)
        {
            if (uri.IsAbsoluteUri)
                return uri.AbsolutePath;

            var original = uri.OriginalString;

            if (original[0] != '/')
                return null;

            var idx = original.IndexOfAny(new[] { '?', '#' });

            return idx > 0 ? original.Substring(0, idx) : original;
        }

        internal static CookieCollection GetCookies(
          this NameValueCollection headers,
          bool response
        )
        {
            var name = response ? "Set-Cookie" : "Cookie";
            var val = headers[name];

            return val != null
                   ? CookieCollection.Parse(val, response)
                   : new CookieCollection();
        }

        internal static string GetDnsSafeHost(this Uri uri, bool bracketIPv6)
        {
            return bracketIPv6 && uri.HostNameType == UriHostNameType.IPv6
                   ? uri.Host
                   : uri.DnsSafeHost;
        }

        internal static string GetErrorMessage(this ushort code)
        {
            switch (code)
            {
                case 1002:
                    return "A protocol error has occurred.";
                case 1003:
                    return "Unsupported data has been received.";
                case 1006:
                    return "An abnormal error has occurred.";
                case 1007:
                    return "Invalid data has been received.";
                case 1008:
                    return "A policy violation has occurred.";
                case 1009:
                    return "A too big message has been received.";
                case 1010:
                    return "The client did not receive expected extension(s).";
                case 1011:
                    return "The server got an internal error.";
                case 1015:
                    return "An error has occurred during a TLS handshake.";
                default:
                    return String.Empty;
            }
        }

        internal static string GetErrorMessage(this CloseStatusCode code)
        {
            return ((ushort)code).GetErrorMessage();
        }

        internal static string GetName(this string nameAndValue, char separator)
        {
            var idx = nameAndValue.IndexOf(separator);

            return idx > 0 ? nameAndValue.Substring(0, idx).Trim() : null;
        }

        internal static string GetUTF8DecodedString(this byte[] bytes)
        {
            try
            {
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return null;
            }
        }

        internal static byte[] GetUTF8EncodedBytes(this string s)
        {
            try
            {
                return Encoding.UTF8.GetBytes(s);
            }
            catch
            {
                return null;
            }
        }

        internal static string GetValue(this string nameAndValue, char separator)
        {
            return nameAndValue.GetValue(separator, false);
        }

        internal static string GetValue(
          this string nameAndValue,
          char separator,
          bool unquote
        )
        {
            var idx = nameAndValue.IndexOf(separator);

            if (idx < 0 || idx == nameAndValue.Length - 1)
                return null;

            var val = nameAndValue.Substring(idx + 1).Trim();

            return unquote ? val.Unquote() : val;
        }

        internal static bool IsCompressionExtension(
          this string value,
          CompressionMethod method
        )
        {
            var extStr = method.ToExtensionString();
            var compType = StringComparison.Ordinal;

            return value.StartsWith(extStr, compType);
        }

        internal static bool IsDefined(this CloseStatusCode code)
        {
            return Enum.IsDefined(typeof(CloseStatusCode), code);
        }

        internal static bool IsEqualTo(
          this int value,
          char c,
          Action<int> beforeComparing
        )
        {
            beforeComparing(value);

            return value == c - 0;
        }

        internal static bool IsHttpMethod(this string value)
        {
            return value == "GET"
                   || value == "HEAD"
                   || value == "POST"
                   || value == "PUT"
                   || value == "DELETE"
                   || value == "CONNECT"
                   || value == "OPTIONS"
                   || value == "TRACE";
        }

        internal static bool IsPortNumber(this int value)
        {
            return value > 0 && value < 65536;
        }

        internal static bool IsReserved(this CloseStatusCode code)
        {
            return ((ushort)code).IsReservedStatusCode();
        }

        internal static bool IsReservedStatusCode(this ushort code)
        {
            return code == 1004
                   || code == 1005
                   || code == 1006
                   || code == 1015;
        }

        internal static bool IsSupportedOpcode(this int opcode)
        {
            return Enum.IsDefined(typeof(Opcode), opcode);
        }

        internal static bool IsText(this string value)
        {
            var len = value.Length;

            for (var i = 0; i < len; i++)
            {
                var c = value[i];

                if (c < 0x20)
                {
                    if ("\r\n\t".IndexOf(c) == -1)
                        return false;

                    if (c == '\n')
                    {
                        i++;

                        if (i == len)
                            break;

                        c = value[i];

                        if (" \t".IndexOf(c) == -1)
                            return false;
                    }

                    continue;
                }

                if (c == 0x7f)
                    return false;
            }

            return true;
        }

        internal static bool IsToken(this string value)
        {
            foreach (var c in value)
            {
                if (c < 0x20)
                    return false;

                if (c > 0x7e)
                    return false;

                if (_tspecials.IndexOf(c) > -1)
                    return false;
            }

            return true;
        }

        internal static bool KeepsAlive(
          this NameValueCollection headers,
          Version version
        )
        {
            var compType = StringComparison.OrdinalIgnoreCase;

            return version > HttpVersion.Version10
                   ? !headers.Contains("Connection", "close", compType)
                   : headers.Contains("Connection", "keep-alive", compType);
        }

        internal static bool MaybeUri(this string value)
        {
            var idx = value.IndexOf(':');

            if (idx < 2 || idx > 9)
                return false;

            var schm = value.Substring(0, idx);

            return schm.isPredefinedScheme();
        }

        internal static string Quote(this string value)
        {
            var fmt = "\"{0}\"";
            var val = value.Replace("\"", "\\\"");

            return String.Format(fmt, val);
        }

        internal static byte[] ReadBytes(this Stream stream, int length)
        {
            var ret = new byte[length];

            var offset = 0;
            var retry = 0;

            while (length > 0)
            {
                var nread = stream.Read(ret, offset, length);

                if (nread <= 0)
                {
                    if (retry < _maxRetry)
                    {
                        retry++;

                        continue;
                    }

                    return ret.SubArray(0, offset);
                }

                retry = 0;

                offset += nread;
                length -= nread;
            }

            return ret;
        }

        internal static byte[] ReadBytes(
          this Stream stream,
          long length,
          int bufferLength
        )
        {
            using (var dest = new MemoryStream())
            {
                var buff = new byte[bufferLength];
                var retry = 0;

                while (length > 0)
                {
                    if (length < bufferLength)
                        bufferLength = (int)length;

                    var nread = stream.Read(buff, 0, bufferLength);

                    if (nread <= 0)
                    {
                        if (retry < _maxRetry)
                        {
                            retry++;

                            continue;
                        }

                        break;
                    }

                    retry = 0;

                    dest.Write(buff, 0, nread);

                    length -= nread;
                }

                dest.Close();

                return dest.ToArray();
            }
        }

        internal static void ReadBytesAsync(
          this Stream stream,
          int length,
          Action<byte[]> completed,
          Action<Exception> error
        )
        {
            var ret = new byte[length];

            var offset = 0;
            var retry = 0;

            AsyncCallback callback = null;
            callback =
              ar => {
                  try
                  {
                      var nread = stream.EndRead(ar);

                      if (nread <= 0)
                      {
                          if (retry < _maxRetry)
                          {
                              retry++;

                              stream.BeginRead(ret, offset, length, callback, null);

                              return;
                          }

                          if (completed != null)
                              completed(ret.SubArray(0, offset));

                          return;
                      }

                      if (nread == length)
                      {
                          if (completed != null)
                              completed(ret);

                          return;
                      }

                      retry = 0;

                      offset += nread;
                      length -= nread;

                      stream.BeginRead(ret, offset, length, callback, null);
                  }
                  catch (Exception ex)
                  {
                      if (error != null)
                          error(ex);
                  }
              };

            try
            {
                stream.BeginRead(ret, offset, length, callback, null);
            }
            catch (Exception ex)
            {
                if (error != null)
                    error(ex);
            }
        }

        internal static void ReadBytesAsync(
          this Stream stream,
          long length,
          int bufferLength,
          Action<byte[]> completed,
          Action<Exception> error
        )
        {
            var dest = new MemoryStream();

            var buff = new byte[bufferLength];
            var retry = 0;

            Action<long> read = null;
            read =
              len => {
                  if (len < bufferLength)
                      bufferLength = (int)len;

                  stream.BeginRead(
              buff,
              0,
              bufferLength,
              ar => {
                      try
                      {
                          var nread = stream.EndRead(ar);

                          if (nread <= 0)
                          {
                              if (retry < _maxRetry)
                              {
                                  retry++;

                                  read(len);

                                  return;
                              }

                              if (completed != null)
                              {
                                  dest.Close();

                                  var ret = dest.ToArray();

                                  completed(ret);
                              }

                              dest.Dispose();

                              return;
                          }

                          dest.Write(buff, 0, nread);

                          if (nread == len)
                          {
                              if (completed != null)
                              {
                                  dest.Close();

                                  var ret = dest.ToArray();

                                  completed(ret);
                              }

                              dest.Dispose();

                              return;
                          }

                          retry = 0;

                          read(len - nread);
                      }
                      catch (Exception ex)
                      {
                          dest.Dispose();

                          if (error != null)
                              error(ex);
                      }
                  },
              null
            );
              };

            try
            {
                read(length);
            }
            catch (Exception ex)
            {
                dest.Dispose();

                if (error != null)
                    error(ex);
            }
        }

        internal static T[] Reverse<T>(this T[] array)
        {
            var len = array.LongLength;
            var ret = new T[len];

            var end = len - 1;

            for (long i = 0; i <= end; i++)
                ret[i] = array[end - i];

            return ret;
        }

        internal static IEnumerable<string> SplitHeaderValue(
          this string value,
          params char[] separators
        )
        {
            var len = value.Length;
            var end = len - 1;

            var buff = new StringBuilder(32);
            var escaped = false;
            var quoted = false;

            for (var i = 0; i <= end; i++)
            {
                var c = value[i];

                buff.Append(c);

                if (c == '"')
                {
                    if (escaped)
                    {
                        escaped = false;

                        continue;
                    }

                    quoted = !quoted;

                    continue;
                }

                if (c == '\\')
                {
                    if (i == end)
                        break;

                    if (value[i + 1] == '"')
                        escaped = true;

                    continue;
                }

                if (Array.IndexOf(separators, c) > -1)
                {
                    if (quoted)
                        continue;

                    buff.Length -= 1;

                    yield return buff.ToString();

                    buff.Length = 0;

                    continue;
                }
            }

            yield return buff.ToString();
        }

        internal static byte[] ToByteArray(this Stream stream)
        {
            stream.Position = 0;

            using (var buff = new MemoryStream())
            {
                stream.CopyTo(buff, 1024);
                buff.Close();

                return buff.ToArray();
            }
        }

        internal static byte[] ToByteArray(this ushort value, ByteOrder order)
        {
            var ret = BitConverter.GetBytes(value);

            if (!order.IsHostOrder())
                Array.Reverse(ret);

            return ret;
        }

        internal static byte[] ToByteArray(this ulong value, ByteOrder order)
        {
            var ret = BitConverter.GetBytes(value);

            if (!order.IsHostOrder())
                Array.Reverse(ret);

            return ret;
        }

        internal static CompressionMethod ToCompressionMethod(this string value)
        {
            var methods = Enum.GetValues(typeof(CompressionMethod));

            foreach (CompressionMethod method in methods)
            {
                if (method.ToExtensionString() == value)
                    return method;
            }

            return CompressionMethod.None;
        }

        internal static string ToExtensionString(
          this CompressionMethod method,
          params string[] parameters
        )
        {
            if (method == CompressionMethod.None)
                return String.Empty;

            var name = method.ToString().ToLower();
            var ename = String.Format("permessage-{0}", name);

            if (parameters == null || parameters.Length == 0)
                return ename;

            var eparams = parameters.ToString("; ");

            return String.Format("{0}; {1}", ename, eparams);
        }

        internal static int ToInt32(this string numericString)
        {
            return Int32.Parse(numericString);
        }

        internal static System.Net.IPAddress ToIPAddress(this string value)
        {
            if (value == null || value.Length == 0)
                return null;

            System.Net.IPAddress addr;

            if (System.Net.IPAddress.TryParse(value, out addr))
                return addr;

            try
            {
                var addrs = System.Net.Dns.GetHostAddresses(value);

                return addrs[0];
            }
            catch
            {
                return null;
            }
        }

        internal static List<TSource> ToList<TSource>(
          this IEnumerable<TSource> source
        )
        {
            return new List<TSource>(source);
        }

        internal static string ToString(
          this System.Net.IPAddress address,
          bool bracketIPv6
        )
        {
            return bracketIPv6
                   && address.AddressFamily == AddressFamily.InterNetworkV6
                   ? String.Format("[{0}]", address)
                   : address.ToString();
        }

        internal static ushort ToUInt16(this byte[] source, ByteOrder sourceOrder)
        {
            var val = source.ToHostOrder(sourceOrder);

            return BitConverter.ToUInt16(val, 0);
        }

        internal static ulong ToUInt64(this byte[] source, ByteOrder sourceOrder)
        {
            var val = source.ToHostOrder(sourceOrder);

            return BitConverter.ToUInt64(val, 0);
        }

        internal static Version ToVersion(this string versionString)
        {
            return new Version(versionString);
        }

        internal static IEnumerable<string> TrimEach(
          this IEnumerable<string> source
        )
        {
            foreach (var elm in source)
                yield return elm.Trim();
        }

        internal static string TrimSlashFromEnd(this string value)
        {
            var ret = value.TrimEnd('/');

            return ret.Length > 0 ? ret : "/";
        }

        internal static string TrimSlashOrBackslashFromEnd(this string value)
        {
            var ret = value.TrimEnd('/', '\\');

            return ret.Length > 0 ? ret : value[0].ToString();
        }

        internal static bool TryCreateVersion(
          this string versionString,
          out Version result
        )
        {
            result = null;

            try
            {
                result = new Version(versionString);
            }
            catch
            {
                return false;
            }

            return true;
        }

        internal static bool TryCreateWebSocketUri(
          this string uriString,
          out Uri result,
          out string message
        )
        {
            result = null;
            message = null;

            var uri = uriString.ToUri();

            if (uri == null)
            {
                message = "An invalid URI string.";

                return false;
            }

            if (!uri.IsAbsoluteUri)
            {
                message = "A relative URI.";

                return false;
            }

            var schm = uri.Scheme;
            var valid = schm == "ws" || schm == "wss";

            if (!valid)
            {
                message = "The scheme part is not \"ws\" or \"wss\".";

                return false;
            }

            var port = uri.Port;

            if (port == 0)
            {
                message = "The port part is zero.";

                return false;
            }

            if (uri.Fragment.Length > 0)
            {
                message = "It includes the fragment component.";

                return false;
            }

            if (port == -1)
            {
                port = schm == "ws" ? 80 : 443;
                uriString = String.Format(
                              "{0}://{1}:{2}{3}",
                              schm,
                              uri.Host,
                              port,
                              uri.PathAndQuery
                            );

                result = new Uri(uriString);
            }
            else
            {
                result = uri;
            }

            return true;
        }

        internal static bool TryGetUTF8DecodedString(
          this byte[] bytes,
          out string s
        )
        {
            s = null;

            try
            {
                s = Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return false;
            }

            return true;
        }

        internal static bool TryGetUTF8EncodedBytes(
          this string s,
          out byte[] bytes
        )
        {
            bytes = null;

            try
            {
                bytes = Encoding.UTF8.GetBytes(s);
            }
            catch
            {
                return false;
            }

            return true;
        }

        internal static bool TryOpenRead(
          this FileInfo fileInfo,
          out FileStream fileStream
        )
        {
            fileStream = null;

            try
            {
                fileStream = fileInfo.OpenRead();
            }
            catch
            {
                return false;
            }

            return true;
        }

        internal static string Unquote(this string value)
        {
            var first = value.IndexOf('"');

            if (first == -1)
                return value;

            var last = value.LastIndexOf('"');

            if (last == first)
                return value;

            var len = last - first - 1;

            return len > 0
                   ? value.Substring(first + 1, len).Replace("\\\"", "\"")
                   : String.Empty;
        }

        internal static bool Upgrades(
          this NameValueCollection headers,
          string protocol
        )
        {
            var compType = StringComparison.OrdinalIgnoreCase;

            return headers.Contains("Upgrade", protocol, compType)
                   && headers.Contains("Connection", "Upgrade", compType);
        }

        internal static string UrlDecode(this string value, Encoding encoding)
        {
            return value.IndexOfAny(new[] { '%', '+' }) > -1
                   ? HttpUtility.UrlDecode(value, encoding)
                   : value;
        }

        internal static string UrlEncode(this string value, Encoding encoding)
        {
            return HttpUtility.UrlEncode(value, encoding);
        }

        internal static void WriteBytes(
          this Stream stream,
          byte[] bytes,
          int bufferLength
        )
        {
            using (var src = new MemoryStream(bytes))
                src.CopyTo(stream, bufferLength);
        }

        internal static void WriteBytesAsync(
          this Stream stream,
          byte[] bytes,
          int bufferLength,
          Action completed,
          Action<Exception> error
        )
        {
            var src = new MemoryStream(bytes);

            src.CopyToAsync(
              stream,
              bufferLength,
              () => {
                  if (completed != null)
                      completed();

                  src.Dispose();
              },
              ex => {
                  src.Dispose();

                  if (error != null)
                      error(ex);
              }
            );
        }

        /// <summary>
        /// Gets the description of the specified HTTP status code.
        /// </summary>
        /// <returns>
        /// A <see cref="string"/> that represents the description of
        /// the HTTP status code.
        /// </returns>
        /// <param name="code">
        ///   <para>
        ///   One of the <see cref="HttpStatusCode"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the HTTP status code.
        ///   </para>
        /// </param>
        public static string GetDescription(this HttpStatusCode code)
        {
            return ((int)code).GetStatusDescription();
        }

        /// <summary>
        /// Gets the description of the specified HTTP status code.
        /// </summary>
        /// <returns>
        ///   <para>
        ///   A <see cref="string"/> that represents the description of
        ///   the HTTP status code.
        ///   </para>
        ///   <para>
        ///   An empty string if the description is not present.
        ///   </para>
        /// </returns>
        /// <param name="code">
        /// An <see cref="int"/> that specifies the HTTP status code.
        /// </param>
        public static string GetStatusDescription(this int code)
        {
            switch (code)
            {
                case 100: return "Continue";
                case 101: return "Switching Protocols";
                case 102: return "Processing";
                case 200: return "OK";
                case 201: return "Created";
                case 202: return "Accepted";
                case 203: return "Non-Authoritative Information";
                case 204: return "No Content";
                case 205: return "Reset Content";
                case 206: return "Partial Content";
                case 207: return "Multi-Status";
                case 300: return "Multiple Choices";
                case 301: return "Moved Permanently";
                case 302: return "Found";
                case 303: return "See Other";
                case 304: return "Not Modified";
                case 305: return "Use Proxy";
                case 307: return "Temporary Redirect";
                case 400: return "Bad Request";
                case 401: return "Unauthorized";
                case 402: return "Payment Required";
                case 403: return "Forbidden";
                case 404: return "Not Found";
                case 405: return "Method Not Allowed";
                case 406: return "Not Acceptable";
                case 407: return "Proxy Authentication Required";
                case 408: return "Request Timeout";
                case 409: return "Conflict";
                case 410: return "Gone";
                case 411: return "Length Required";
                case 412: return "Precondition Failed";
                case 413: return "Request Entity Too Large";
                case 414: return "Request-Uri Too Long";
                case 415: return "Unsupported Media Type";
                case 416: return "Requested Range Not Satisfiable";
                case 417: return "Expectation Failed";
                case 422: return "Unprocessable Entity";
                case 423: return "Locked";
                case 424: return "Failed Dependency";
                case 500: return "Internal Server Error";
                case 501: return "Not Implemented";
                case 502: return "Bad Gateway";
                case 503: return "Service Unavailable";
                case 504: return "Gateway Timeout";
                case 505: return "Http Version Not Supported";
                case 507: return "Insufficient Storage";
            }

            return String.Empty;
        }

        /// <summary>
        /// Determines whether the specified ushort is in the range of
        /// the status code for the WebSocket connection close.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   The ranges are the following:
        ///   </para>
        ///   <list type="bullet">
        ///     <item>
        ///       <term>
        ///       1000-2999: These numbers are reserved for definition by
        ///       the WebSocket protocol.
        ///       </term>
        ///     </item>
        ///     <item>
        ///       <term>
        ///       3000-3999: These numbers are reserved for use by libraries,
        ///       frameworks, and applications.
        ///       </term>
        ///     </item>
        ///     <item>
        ///       <term>
        ///       4000-4999: These numbers are reserved for private use.
        ///       </term>
        ///     </item>
        ///   </list>
        /// </remarks>
        /// <returns>
        /// <c>true</c> if <paramref name="value"/> is in the range of
        /// the status code for the close; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="value">
        /// A <see cref="ushort"/> to test.
        /// </param>
        public static bool IsCloseStatusCode(this ushort value)
        {
            return value > 999 && value < 5000;
        }

        /// <summary>
        /// Determines whether the specified string is enclosed in
        /// the specified character.
        /// </summary>
        /// <returns>
        /// <c>true</c> if <paramref name="value"/> is enclosed in
        /// <paramref name="c"/>; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="value">
        /// A <see cref="string"/> to test.
        /// </param>
        /// <param name="c">
        /// A <see cref="char"/> to find.
        /// </param>
        public static bool IsEnclosedIn(this string value, char c)
        {
            if (value == null)
                return false;

            var len = value.Length;

            return len > 1 ? value[0] == c && value[len - 1] == c : false;
        }

        /// <summary>
        /// Determines whether the specified byte order is host (this computer
        /// architecture) byte order.
        /// </summary>
        /// <returns>
        /// <c>true</c> if <paramref name="order"/> is host byte order; otherwise,
        /// <c>false</c>.
        /// </returns>
        /// <param name="order">
        /// One of the <see cref="ByteOrder"/> enum values to test.
        /// </param>
        public static bool IsHostOrder(this ByteOrder order)
        {
            // true: !(true ^ true) or !(false ^ false)
            // false: !(true ^ false) or !(false ^ true)
            return !(BitConverter.IsLittleEndian ^ (order == ByteOrder.Little));
        }

        /// <summary>
        /// Determines whether the specified IP address is a local IP address.
        /// </summary>
        /// <remarks>
        /// This local means NOT REMOTE for the current host.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if <paramref name="address"/> is a local IP address;
        /// otherwise, <c>false</c>.
        /// </returns>
        /// <param name="address">
        /// A <see cref="System.Net.IPAddress"/> to test.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="address"/> is <see langword="null"/>.
        /// </exception>
        public static bool IsLocal(this System.Net.IPAddress address)
        {
            if (address == null)
                throw new ArgumentNullException("address");

            if (address.Equals(System.Net.IPAddress.Any))
                return true;

            if (address.Equals(System.Net.IPAddress.Loopback))
                return true;

            if (Socket.OSSupportsIPv6)
            {
                if (address.Equals(System.Net.IPAddress.IPv6Any))
                    return true;

                if (address.Equals(System.Net.IPAddress.IPv6Loopback))
                    return true;
            }

            var name = System.Net.Dns.GetHostName();
            var addrs = System.Net.Dns.GetHostAddresses(name);

            foreach (var addr in addrs)
            {
                if (address.Equals(addr))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Determines whether the specified string is <see langword="null"/> or
        /// an empty string.
        /// </summary>
        /// <returns>
        /// <c>true</c> if <paramref name="value"/> is <see langword="null"/> or
        /// an empty string; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="value">
        /// A <see cref="string"/> to test.
        /// </param>
        public static bool IsNullOrEmpty(this string value)
        {
            return value == null || value.Length == 0;
        }

        /// <summary>
        /// Retrieves a sub-array from the specified array. A sub-array starts at
        /// the specified index in the array.
        /// </summary>
        /// <returns>
        /// An array of T that receives a sub-array.
        /// </returns>
        /// <param name="array">
        /// An array of T from which to retrieve a sub-array.
        /// </param>
        /// <param name="startIndex">
        /// An <see cref="int"/> that specifies the zero-based index in the array
        /// at which retrieving starts.
        /// </param>
        /// <param name="length">
        /// An <see cref="int"/> that specifies the number of elements to retrieve.
        /// </param>
        /// <typeparam name="T">
        /// The type of elements in the array.
        /// </typeparam>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="array"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <para>
        ///   <paramref name="startIndex"/> is less than zero.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="startIndex"/> is greater than the end of the array.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is less than zero.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is greater than the number of elements from
        ///   <paramref name="startIndex"/> to the end of the array.
        ///   </para>
        /// </exception>
        public static T[] SubArray<T>(this T[] array, int startIndex, int length)
        {
            if (array == null)
                throw new ArgumentNullException("array");

            var len = array.Length;

            if (len == 0)
            {
                if (startIndex != 0)
                    throw new ArgumentOutOfRangeException("startIndex");

                if (length != 0)
                    throw new ArgumentOutOfRangeException("length");

                return array;
            }

            if (startIndex < 0 || startIndex >= len)
                throw new ArgumentOutOfRangeException("startIndex");

            if (length < 0 || length > len - startIndex)
                throw new ArgumentOutOfRangeException("length");

            if (length == 0)
                return new T[0];

            if (length == len)
                return array;

            var ret = new T[length];

            Array.Copy(array, startIndex, ret, 0, length);

            return ret;
        }

        /// <summary>
        /// Retrieves a sub-array from the specified array. A sub-array starts at
        /// the specified index in the array.
        /// </summary>
        /// <returns>
        /// An array of T that receives a sub-array.
        /// </returns>
        /// <param name="array">
        /// An array of T from which to retrieve a sub-array.
        /// </param>
        /// <param name="startIndex">
        /// A <see cref="long"/> that specifies the zero-based index in the array
        /// at which retrieving starts.
        /// </param>
        /// <param name="length">
        /// A <see cref="long"/> that specifies the number of elements to retrieve.
        /// </param>
        /// <typeparam name="T">
        /// The type of elements in the array.
        /// </typeparam>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="array"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <para>
        ///   <paramref name="startIndex"/> is less than zero.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="startIndex"/> is greater than the end of the array.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is less than zero.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is greater than the number of elements from
        ///   <paramref name="startIndex"/> to the end of the array.
        ///   </para>
        /// </exception>
        public static T[] SubArray<T>(this T[] array, long startIndex, long length)
        {
            if (array == null)
                throw new ArgumentNullException("array");

            var len = array.LongLength;

            if (len == 0)
            {
                if (startIndex != 0)
                    throw new ArgumentOutOfRangeException("startIndex");

                if (length != 0)
                    throw new ArgumentOutOfRangeException("length");

                return array;
            }

            if (startIndex < 0 || startIndex >= len)
                throw new ArgumentOutOfRangeException("startIndex");

            if (length < 0 || length > len - startIndex)
                throw new ArgumentOutOfRangeException("length");

            if (length == 0)
                return new T[0];

            if (length == len)
                return array;

            var ret = new T[length];

            Array.Copy(array, startIndex, ret, 0, length);

            return ret;
        }

        /// <summary>
        /// Executes the specified delegate <paramref name="n"/> times.
        /// </summary>
        /// <param name="n">
        /// An <see cref="int"/> that specifies the number of times to execute.
        /// </param>
        /// <param name="action">
        ///   <para>
        ///   An <c>Action&lt;int&gt;</c> delegate to execute.
        ///   </para>
        ///   <para>
        ///   The <see cref="int"/> parameter is the zero-based count of iteration.
        ///   </para>
        /// </param>
        public static void Times(this int n, Action<int> action)
        {
            if (n <= 0)
                return;

            if (action == null)
                return;

            for (int i = 0; i < n; i++)
                action(i);
        }

        /// <summary>
        /// Executes the specified delegate <paramref name="n"/> times.
        /// </summary>
        /// <param name="n">
        /// A <see cref="long"/> that specifies the number of times to execute.
        /// </param>
        /// <param name="action">
        ///   <para>
        ///   An <c>Action&lt;long&gt;</c> delegate to execute.
        ///   </para>
        ///   <para>
        ///   The <see cref="long"/> parameter is the zero-based count of iteration.
        ///   </para>
        /// </param>
        public static void Times(this long n, Action<long> action)
        {
            if (n <= 0)
                return;

            if (action == null)
                return;

            for (long i = 0; i < n; i++)
                action(i);
        }

        /// <summary>
        /// Converts the order of elements in the specified byte array to
        /// host (this computer architecture) byte order.
        /// </summary>
        /// <returns>
        ///   <para>
        ///   An array of <see cref="byte"/> converted from
        ///   <paramref name="source"/>.
        ///   </para>
        ///   <para>
        ///   <paramref name="source"/> if the number of elements in
        ///   it is less than 2 or <paramref name="sourceOrder"/> is
        ///   same as host byte order.
        ///   </para>
        /// </returns>
        /// <param name="source">
        /// An array of <see cref="byte"/> to convert.
        /// </param>
        /// <param name="sourceOrder">
        ///   <para>
        ///   One of the <see cref="ByteOrder"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the order of elements in <paramref name="source"/>.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="source"/> is <see langword="null"/>.
        /// </exception>
        public static byte[] ToHostOrder(this byte[] source, ByteOrder sourceOrder)
        {
            if (source == null)
                throw new ArgumentNullException("source");

            if (source.Length < 2)
                return source;

            if (sourceOrder.IsHostOrder())
                return source;

            return source.Reverse();
        }

        /// <summary>
        /// Converts the specified array to a string.
        /// </summary>
        /// <returns>
        ///   <para>
        ///   A <see cref="string"/> converted by concatenating each element of
        ///   <paramref name="array"/> across <paramref name="separator"/>.
        ///   </para>
        ///   <para>
        ///   An empty string if <paramref name="array"/> is an empty array.
        ///   </para>
        /// </returns>
        /// <param name="array">
        /// An array of T to convert.
        /// </param>
        /// <param name="separator">
        /// A <see cref="string"/> used to separate each element of
        /// <paramref name="array"/>.
        /// </param>
        /// <typeparam name="T">
        /// The type of elements in <paramref name="array"/>.
        /// </typeparam>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="array"/> is <see langword="null"/>.
        /// </exception>
        public static string ToString<T>(this T[] array, string separator)
        {
            if (array == null)
                throw new ArgumentNullException("array");

            var len = array.Length;

            if (len == 0)
                return String.Empty;

            var buff = new StringBuilder(64);
            var end = len - 1;

            for (var i = 0; i < end; i++)
                buff.AppendFormat("{0}{1}", array[i], separator);

            buff.AppendFormat("{0}", array[end]);

            return buff.ToString();
        }

        /// <summary>
        /// Converts the specified string to a <see cref="Uri"/>.
        /// </summary>
        /// <returns>
        ///   <para>
        ///   A <see cref="Uri"/> converted from <paramref name="value"/>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if the conversion has failed.
        ///   </para>
        /// </returns>
        /// <param name="value">
        /// A <see cref="string"/> to convert.
        /// </param>
        public static Uri ToUri(this string value)
        {
            if (value == null || value.Length == 0)
                return null;

            var kind = value.MaybeUri() ? UriKind.Absolute : UriKind.Relative;
            Uri ret;

            Uri.TryCreate(value, kind, out ret);

            return ret;
        }
    }
    //==========================================================================================
    /// <summary>
    /// Indicates whether a WebSocket frame is the final frame of a message.
    /// </summary>
    /// <remarks>
    /// The values of this enumeration are defined in
    /// <see href="http://tools.ietf.org/html/rfc6455#section-5.2">
    /// Section 5.2</see> of RFC 6455.
    /// </remarks>
    internal enum Fin
    {
        /// <summary>
        /// Equivalent to numeric value 0. Indicates more frames of a message follow.
        /// </summary>
        More = 0x0,
        /// <summary>
        /// Equivalent to numeric value 1. Indicates the final frame of a message.
        /// </summary>
        Final = 0x1
    }
    //==========================================================================================
    internal abstract class HttpBase
    {
        private NameValueCollection _headers;
        private static readonly int _maxMessageHeaderLength;
        private string _messageBody;
        private byte[] _messageBodyData;
        private Version _version;

        protected static readonly string CrLf;
        protected static readonly string CrLfHt;
        protected static readonly string CrLfSp;

        static HttpBase()
        {
            _maxMessageHeaderLength = 8192;

            CrLf = "\r\n";
            CrLfHt = "\r\n\t";
            CrLfSp = "\r\n ";
        }

        protected HttpBase(Version version, NameValueCollection headers)
        {
            _version = version;
            _headers = headers;
        }

        internal byte[] MessageBodyData
        {
            get
            {
                return _messageBodyData;
            }
        }

        protected string HeaderSection
        {
            get
            {
                var buff = new StringBuilder(64);

                var fmt = "{0}: {1}{2}";

                foreach (var key in _headers.AllKeys)
                    buff.AppendFormat(fmt, key, _headers[key], CrLf);

                buff.Append(CrLf);

                return buff.ToString();
            }
        }

        public bool HasMessageBody
        {
            get
            {
                return _messageBodyData != null;
            }
        }

        public NameValueCollection Headers
        {
            get
            {
                return _headers;
            }
        }

        public string MessageBody
        {
            get
            {
                if (_messageBody == null)
                    _messageBody = getMessageBody();

                return _messageBody;
            }
        }

        public abstract string MessageHeader { get; }

        public Version ProtocolVersion
        {
            get
            {
                return _version;
            }
        }

        private string getMessageBody()
        {
            if (_messageBodyData == null || _messageBodyData.LongLength == 0)
                return String.Empty;

            var contentType = _headers["Content-Type"];

            var enc = contentType != null && contentType.Length > 0
                      ? HttpUtility.GetEncoding(contentType)
                      : Encoding.UTF8;

            return enc.GetString(_messageBodyData);
        }

        private static byte[] readMessageBodyFrom(Stream stream, string length)
        {
            long len;

            if (!Int64.TryParse(length, out len))
            {
                var msg = "It could not be parsed.";

                throw new ArgumentException(msg, "length");
            }

            if (len < 0)
            {
                var msg = "Less than zero.";

                throw new ArgumentOutOfRangeException("length", msg);
            }

            return len > 1024
                   ? stream.ReadBytes(len, 1024)
                   : len > 0
                     ? stream.ReadBytes((int)len)
                     : null;
        }

        private static string[] readMessageHeaderFrom(Stream stream)
        {
            var buff = new List<byte>();
            var cnt = 0;
            Action<int> add =
              i => {
                  if (i == -1)
                  {
                      var msg = "The header could not be read from the data stream.";

                      throw new EndOfStreamException(msg);
                  }

                  buff.Add((byte)i);

                  cnt++;
              };

            var end = false;

            do
            {
                end = stream.ReadByte().IsEqualTo('\r', add)
                      && stream.ReadByte().IsEqualTo('\n', add)
                      && stream.ReadByte().IsEqualTo('\r', add)
                      && stream.ReadByte().IsEqualTo('\n', add);

                if (cnt > _maxMessageHeaderLength)
                {
                    var msg = "The length of the header is greater than the max length.";

                    throw new InvalidOperationException(msg);
                }
            }
            while (!end);

            var bytes = buff.ToArray();

            return Encoding.UTF8.GetString(bytes)
                   .Replace(CrLfSp, " ")
                   .Replace(CrLfHt, " ")
                   .Split(new[] { CrLf }, StringSplitOptions.RemoveEmptyEntries);
        }

        internal void WriteTo(Stream stream)
        {
            var bytes = ToByteArray();

            stream.Write(bytes, 0, bytes.Length);
        }

        protected static T Read<T>(
          Stream stream,
          Func<string[], T> parser,
          int millisecondsTimeout
        )
          where T : HttpBase
        {
            T ret = null;

            var timeout = false;
            var timer = new Timer(
                          state => {
                              timeout = true;

                              stream.Close();
                          },
                          null,
                          millisecondsTimeout,
                          -1
                        );

            Exception exception = null;

            try
            {
                var header = readMessageHeaderFrom(stream);
                ret = parser(header);

                var contentLen = ret.Headers["Content-Length"];

                if (contentLen != null && contentLen.Length > 0)
                    ret._messageBodyData = readMessageBodyFrom(stream, contentLen);
            }
            catch (Exception ex)
            {
                exception = ex;
            }
            finally
            {
                timer.Change(-1, -1);
                timer.Dispose();
            }

            if (timeout)
            {
                var msg = "A timeout has occurred.";

                throw new WebSocketException(msg);
            }

            if (exception != null)
            {
                var msg = "An exception has occurred.";

                throw new WebSocketException(msg, exception);
            }

            return ret;
        }

        public byte[] ToByteArray()
        {
            var headerData = Encoding.UTF8.GetBytes(MessageHeader);

            return _messageBodyData != null
                   ? headerData.Concat(_messageBodyData).ToArray()
                   : headerData;
        }

        public override string ToString()
        {
            return _messageBodyData != null
                   ? MessageHeader + MessageBody
                   : MessageHeader;
        }
    }
    //===================================================================================
    internal class HttpRequest : HttpBase
    {
        private CookieCollection _cookies;
        private string _method;
        private string _target;

        private HttpRequest(
          string method,
          string target,
          Version version,
          NameValueCollection headers
        )
          : base(version, headers)
        {
            _method = method;
            _target = target;
        }

        internal HttpRequest(string method, string target)
          : this(method, target, HttpVersion.Version11, new NameValueCollection())
        {
            Headers["User-Agent"] = "websocket-sharp/1.0";
        }

        internal string RequestLine
        {
            get
            {
                var fmt = "{0} {1} HTTP/{2}{3}";

                return String.Format(fmt, _method, _target, ProtocolVersion, CrLf);
            }
        }

        public AuthenticationResponse AuthenticationResponse
        {
            get
            {
                var val = Headers["Authorization"];

                return val != null && val.Length > 0
                       ? AuthenticationResponse.Parse(val)
                       : null;
            }
        }

        public CookieCollection Cookies
        {
            get
            {
                if (_cookies == null)
                    _cookies = Headers.GetCookies(false);

                return _cookies;
            }
        }

        public string HttpMethod
        {
            get
            {
                return _method;
            }
        }

        public bool IsWebSocketRequest
        {
            get
            {
                return _method == "GET"
                       && ProtocolVersion > HttpVersion.Version10
                       && Headers.Upgrades("websocket");
            }
        }

        public override string MessageHeader
        {
            get
            {
                return RequestLine + HeaderSection;
            }
        }

        public string RequestTarget
        {
            get
            {
                return _target;
            }
        }

        internal static HttpRequest CreateConnectRequest(Uri targetUri)
        {
            var fmt = "{0}:{1}";
            var host = targetUri.DnsSafeHost;
            var port = targetUri.Port;
            var authority = String.Format(fmt, host, port);

            var ret = new HttpRequest("CONNECT", authority);

            ret.Headers["Host"] = port != 80 ? authority : host;

            return ret;
        }

        internal static HttpRequest CreateWebSocketHandshakeRequest(Uri targetUri)
        {
            var ret = new HttpRequest("GET", targetUri.PathAndQuery);

            var headers = ret.Headers;

            var port = targetUri.Port;
            var schm = targetUri.Scheme;
            var isDefaultPort = (port == 80 && schm == "ws")
                                || (port == 443 && schm == "wss");

            headers["Host"] = !isDefaultPort
                              ? targetUri.Authority
                              : targetUri.DnsSafeHost;

            headers["Upgrade"] = "websocket";
            headers["Connection"] = "Upgrade";

            return ret;
        }

        internal HttpResponse GetResponse(Stream stream, int millisecondsTimeout)
        {
            WriteTo(stream);

            return HttpResponse.ReadResponse(stream, millisecondsTimeout);
        }

        internal static HttpRequest Parse(string[] messageHeader)
        {
            var len = messageHeader.Length;

            if (len == 0)
            {
                var msg = "An empty request header.";

                throw new ArgumentException(msg);
            }

            var rlParts = messageHeader[0].Split(new[] { ' ' }, 3);

            if (rlParts.Length != 3)
            {
                var msg = "It includes an invalid request line.";

                throw new ArgumentException(msg);
            }

            var method = rlParts[0];
            var target = rlParts[1];
            var ver = rlParts[2].Substring(5).ToVersion();

            var headers = new WebHeaderCollection();

            for (var i = 1; i < len; i++)
                headers.InternalSet(messageHeader[i], false);

            return new HttpRequest(method, target, ver, headers);
        }

        internal static HttpRequest ReadRequest(
          Stream stream,
          int millisecondsTimeout
        )
        {
            return Read<HttpRequest>(stream, Parse, millisecondsTimeout);
        }

        public void SetCookies(CookieCollection cookies)
        {
            if (cookies == null || cookies.Count == 0)
                return;

            var buff = new StringBuilder(64);

            foreach (var cookie in cookies.Sorted)
            {
                if (cookie.Expired)
                    continue;

                buff.AppendFormat("{0}; ", cookie);
            }

            var len = buff.Length;

            if (len <= 2)
                return;

            buff.Length = len - 2;

            Headers["Cookie"] = buff.ToString();
        }
    }
    //======================================================================================
    internal class HttpResponse : HttpBase
    {
        private int _code;
        private string _reason;

        private HttpResponse(
          int code,
          string reason,
          Version version,
          NameValueCollection headers
        )
          : base(version, headers)
        {
            _code = code;
            _reason = reason;
        }

        internal HttpResponse(int code)
          : this(code, code.GetStatusDescription())
        {
        }

        internal HttpResponse(HttpStatusCode code)
          : this((int)code)
        {
        }

        internal HttpResponse(int code, string reason)
          : this(
              code,
              reason,
              HttpVersion.Version11,
              new NameValueCollection()
            )
        {
            Headers["Server"] = "websocket-sharp/1.0";
        }

        internal HttpResponse(HttpStatusCode code, string reason)
          : this((int)code, reason)
        {
        }

        internal string StatusLine
        {
            get
            {
                return _reason != null
                       ? String.Format(
                           "HTTP/{0} {1} {2}{3}",
                           ProtocolVersion,
                           _code,
                           _reason,
                           CrLf
                         )
                       : String.Format(
                           "HTTP/{0} {1}{2}",
                           ProtocolVersion,
                           _code,
                           CrLf
                         );
            }
        }

        public bool CloseConnection
        {
            get
            {
                var compType = StringComparison.OrdinalIgnoreCase;

                return Headers.Contains("Connection", "close", compType);
            }
        }

        public CookieCollection Cookies
        {
            get
            {
                return Headers.GetCookies(true);
            }
        }

        public bool IsProxyAuthenticationRequired
        {
            get
            {
                return _code == 407;
            }
        }

        public bool IsRedirect
        {
            get
            {
                return _code == 301 || _code == 302;
            }
        }

        public bool IsSuccess
        {
            get
            {
                return _code >= 200 && _code <= 299;
            }
        }

        public bool IsUnauthorized
        {
            get
            {
                return _code == 401;
            }
        }

        public bool IsWebSocketResponse
        {
            get
            {
                return ProtocolVersion > HttpVersion.Version10
                       && _code == 101
                       && Headers.Upgrades("websocket");
            }
        }

        public override string MessageHeader
        {
            get
            {
                return StatusLine + HeaderSection;
            }
        }

        public string Reason
        {
            get
            {
                return _reason;
            }
        }

        public int StatusCode
        {
            get
            {
                return _code;
            }
        }

        internal static HttpResponse CreateCloseResponse(HttpStatusCode code)
        {
            var ret = new HttpResponse(code);

            ret.Headers["Connection"] = "close";

            return ret;
        }

        internal static HttpResponse CreateUnauthorizedResponse(string challenge)
        {
            var ret = new HttpResponse(HttpStatusCode.Unauthorized);

            ret.Headers["WWW-Authenticate"] = challenge;

            return ret;
        }

        internal static HttpResponse CreateWebSocketHandshakeResponse()
        {
            var ret = new HttpResponse(HttpStatusCode.SwitchingProtocols);

            var headers = ret.Headers;

            headers["Upgrade"] = "websocket";
            headers["Connection"] = "Upgrade";

            return ret;
        }

        internal static HttpResponse Parse(string[] messageHeader)
        {
            var len = messageHeader.Length;

            if (len == 0)
            {
                var msg = "An empty response header.";

                throw new ArgumentException(msg);
            }

            var slParts = messageHeader[0].Split(new[] { ' ' }, 3);
            var plen = slParts.Length;

            if (plen < 2)
            {
                var msg = "It includes an invalid status line.";

                throw new ArgumentException(msg);
            }

            var code = slParts[1].ToInt32();
            var reason = plen == 3 ? slParts[2] : null;
            var ver = slParts[0].Substring(5).ToVersion();

            var headers = new WebHeaderCollection();

            for (var i = 1; i < len; i++)
                headers.InternalSet(messageHeader[i], true);

            return new HttpResponse(code, reason, ver, headers);
        }

        internal static HttpResponse ReadResponse(
          Stream stream,
          int millisecondsTimeout
        )
        {
            return Read<HttpResponse>(stream, Parse, millisecondsTimeout);
        }

        public void SetCookies(CookieCollection cookies)
        {
            if (cookies == null || cookies.Count == 0)
                return;

            var headers = Headers;

            foreach (var cookie in cookies.Sorted)
            {
                var val = cookie.ToResponseString();

                headers.Add("Set-Cookie", val);
            }
        }
    }
    //================================================================================================
    /// <summary>
    /// Represents a log data used by the <see cref="Logger"/> class.
    /// </summary>
    public class LogData
    {
        private StackFrame _caller;
        private DateTime _date;
        private LogLevel _level;
        private string _message;

        internal LogData(LogLevel level, StackFrame caller, string message)
        {
            _level = level;
            _caller = caller;
            _message = message ?? String.Empty;

            _date = DateTime.Now;
        }

        /// <summary>
        /// Gets the information of the logging method caller.
        /// </summary>
        /// <value>
        /// A <see cref="StackFrame"/> that provides the information of
        /// the logging method caller.
        /// </value>
        public StackFrame Caller
        {
            get
            {
                return _caller;
            }
        }

        /// <summary>
        /// Gets the date and time when the log data was created.
        /// </summary>
        /// <value>
        /// A <see cref="DateTime"/> that represents the date and time when
        /// the log data was created.
        /// </value>
        public DateTime Date
        {
            get
            {
                return _date;
            }
        }

        /// <summary>
        /// Gets the logging level of the log data.
        /// </summary>
        /// <value>
        ///   <para>
        ///   One of the <see cref="LogLevel"/> enum values.
        ///   </para>
        ///   <para>
        ///   It represents the logging level of the log data.
        ///   </para>
        /// </value>
        public LogLevel Level
        {
            get
            {
                return _level;
            }
        }

        /// <summary>
        /// Gets the message of the log data.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the message of the log data.
        /// </value>
        public string Message
        {
            get
            {
                return _message;
            }
        }

        /// <summary>
        /// Returns a string that represents the current instance.
        /// </summary>
        /// <returns>
        /// A <see cref="string"/> that represents the current instance.
        /// </returns>
        public override string ToString()
        {
            var date = String.Format("[{0}]", _date);
            var level = String.Format("{0,-5}", _level.ToString().ToUpper());

            var method = _caller.GetMethod();
            var type = method.DeclaringType;
#if DEBUG
            var num = _caller.GetFileLineNumber();
            var caller = String.Format("{0}.{1}:{2}", type.Name, method.Name, num);
#else
      var caller = String.Format ("{0}.{1}", type.Name, method.Name);
#endif
            var msgs = _message.Replace("\r\n", "\n").TrimEnd('\n').Split('\n');

            if (msgs.Length <= 1)
                return String.Format("{0} {1} {2} {3}", date, level, caller, _message);

            var buff = new StringBuilder(64);

            buff.AppendFormat("{0} {1} {2}\n\n", date, level, caller);

            foreach (var msg in msgs)
                buff.AppendFormat("  {0}\n", msg);

            return buff.ToString();
        }
    }
    //============================================================================================
    /// <summary>
    /// Provides a set of methods and properties for logging.
    /// </summary>
    /// <remarks>
    ///   <para>
    ///   If you output a log with lower than the current logging level,
    ///   it cannot be outputted.
    ///   </para>
    ///   <para>
    ///   The default output method writes a log to the standard output
    ///   stream and the text file if it has a valid path.
    ///   </para>
    ///   <para>
    ///   If you would like to use the custom output method, you should
    ///   specify it with the constructor or the <see cref="Logger.Output"/>
    ///   property.
    ///   </para>
    /// </remarks>
    public class Logger
    {
        private volatile string _file;
        private volatile LogLevel _level;
        private Action<LogData, string> _output;
        private object _sync;

        /// <summary>
        /// Initializes a new instance of the <see cref="Logger"/> class.
        /// </summary>
        /// <remarks>
        /// This constructor initializes the logging level with the Error level.
        /// </remarks>
        public Logger()
          : this(LogLevel.Error, null, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Logger"/> class with
        /// the specified logging level.
        /// </summary>
        /// <param name="level">
        /// One of the <see cref="LogLevel"/> enum values that specifies
        /// the logging level.
        /// </param>
        public Logger(LogLevel level)
          : this(level, null, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Logger"/> class with
        /// the specified logging level, path to the log file, and delegate
        /// used to output a log.
        /// </summary>
        /// <param name="level">
        /// One of the <see cref="LogLevel"/> enum values that specifies
        /// the logging level.
        /// </param>
        /// <param name="file">
        /// A <see cref="string"/> that specifies the path to the log file.
        /// </param>
        /// <param name="output">
        /// An <see cref="T:System.Action{LogData, string}"/> that specifies
        /// the delegate used to output a log.
        /// </param>
        public Logger(LogLevel level, string file, Action<LogData, string> output)
        {
            _level = level;
            _file = file;
            _output = output ?? defaultOutput;

            _sync = new object();
        }

        /// <summary>
        /// Gets or sets the path to the log file.
        /// </summary>
        /// <value>
        /// A <see cref="string"/> that represents the path to the log file if any.
        /// </value>
        public string File
        {
            get
            {
                return _file;
            }

            set
            {
                lock (_sync)
                    _file = value;
            }
        }

        /// <summary>
        /// Gets or sets the current logging level.
        /// </summary>
        /// <remarks>
        /// A log with lower than the value of this property cannot be outputted.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   One of the <see cref="LogLevel"/> enum values.
        ///   </para>
        ///   <para>
        ///   It represents the current logging level.
        ///   </para>
        /// </value>
        public LogLevel Level
        {
            get
            {
                return _level;
            }

            set
            {
                lock (_sync)
                    _level = value;
            }
        }

        /// <summary>
        /// Gets or sets the delegate used to output a log.
        /// </summary>
        /// <value>
        ///   <para>
        ///   An <see cref="T:System.Action{LogData, string}"/> delegate.
        ///   </para>
        ///   <para>
        ///   It represents the delegate called when the logger outputs a log.
        ///   </para>
        ///   <para>
        ///   The string parameter passed to the delegate is the value of
        ///   the <see cref="Logger.File"/> property.
        ///   </para>
        ///   <para>
        ///   If the value to set is <see langword="null"/>, the default
        ///   output method is set.
        ///   </para>
        /// </value>
        public Action<LogData, string> Output
        {
            get
            {
                return _output;
            }

            set
            {
                lock (_sync)
                    _output = value ?? defaultOutput;
            }
        }

        private static void defaultOutput(LogData data, string path)
        {
            var val = data.ToString();

            Console.WriteLine(val);

            if (path != null && path.Length > 0)
                writeToFile(val, path);
        }

        private void output(string message, LogLevel level)
        {
            lock (_sync)
            {
                if (_level > level)
                    return;

                try
                {
                    var data = new LogData(level, new StackFrame(2, true), message);

                    _output(data, _file);
                }
                catch (Exception ex)
                {
                    var data = new LogData(
                                 LogLevel.Fatal,
                                 new StackFrame(0, true),
                                 ex.Message
                               );

                    Console.WriteLine(data.ToString());
                }
            }
        }

        private static void writeToFile(string value, string path)
        {
            using (var writer = new StreamWriter(path, true))
            using (var syncWriter = TextWriter.Synchronized(writer))
                syncWriter.WriteLine(value);
        }

        /// <summary>
        /// Outputs the specified message as a log with the Debug level.
        /// </summary>
        /// <remarks>
        /// If the current logging level is higher than the Debug level,
        /// this method does not output the message as a log.
        /// </remarks>
        /// <param name="message">
        /// A <see cref="string"/> that specifies the message to output.
        /// </param>
        public void Debug(string message)
        {
            if (_level > LogLevel.Debug)
                return;

            output(message, LogLevel.Debug);
        }

        /// <summary>
        /// Outputs the specified message as a log with the Error level.
        /// </summary>
        /// <remarks>
        /// If the current logging level is higher than the Error level,
        /// this method does not output the message as a log.
        /// </remarks>
        /// <param name="message">
        /// A <see cref="string"/> that specifies the message to output.
        /// </param>
        public void Error(string message)
        {
            if (_level > LogLevel.Error)
                return;

            output(message, LogLevel.Error);
        }

        /// <summary>
        /// Outputs the specified message as a log with the Fatal level.
        /// </summary>
        /// <param name="message">
        /// A <see cref="string"/> that specifies the message to output.
        /// </param>
        public void Fatal(string message)
        {
            if (_level > LogLevel.Fatal)
                return;

            output(message, LogLevel.Fatal);
        }

        /// <summary>
        /// Outputs the specified message as a log with the Info level.
        /// </summary>
        /// <remarks>
        /// If the current logging level is higher than the Info level,
        /// this method does not output the message as a log.
        /// </remarks>
        /// <param name="message">
        /// A <see cref="string"/> that specifies the message to output.
        /// </param>
        public void Info(string message)
        {
            if (_level > LogLevel.Info)
                return;

            output(message, LogLevel.Info);
        }

        /// <summary>
        /// Outputs the specified message as a log with the Trace level.
        /// </summary>
        /// <remarks>
        /// If the current logging level is higher than the Trace level,
        /// this method does not output the message as a log.
        /// </remarks>
        /// <param name="message">
        /// A <see cref="string"/> that specifies the message to output.
        /// </param>
        public void Trace(string message)
        {
            if (_level > LogLevel.Trace)
                return;

            output(message, LogLevel.Trace);
        }

        /// <summary>
        /// Outputs the specified message as a log with the Warn level.
        /// </summary>
        /// <remarks>
        /// If the current logging level is higher than the Warn level,
        /// this method does not output the message as a log.
        /// </remarks>
        /// <param name="message">
        /// A <see cref="string"/> that specifies the message to output.
        /// </param>
        public void Warn(string message)
        {
            if (_level > LogLevel.Warn)
                return;

            output(message, LogLevel.Warn);
        }
    }
    //===========================================================================================
    /// <summary>
    /// Specifies the logging level.
    /// </summary>
    public enum LogLevel
    {
        /// <summary>
        /// Specifies the bottom logging level.
        /// </summary>
        Trace,
        /// <summary>
        /// Specifies the 2nd logging level from the bottom.
        /// </summary>
        Debug,
        /// <summary>
        /// Specifies the 3rd logging level from the bottom.
        /// </summary>
        Info,
        /// <summary>
        /// Specifies the 3rd logging level from the top.
        /// </summary>
        Warn,
        /// <summary>
        /// Specifies the 2nd logging level from the top.
        /// </summary>
        Error,
        /// <summary>
        /// Specifies the top logging level.
        /// </summary>
        Fatal,
        /// <summary>
        /// Specifies not to output logs.
        /// </summary>
        None
    }
    //=========================================================================================
    /// <summary>
    /// Indicates whether the payload data of a WebSocket frame is masked.
    /// </summary>
    /// <remarks>
    /// The values of this enumeration are defined in
    /// <see href="http://tools.ietf.org/html/rfc6455#section-5.2">
    /// Section 5.2</see> of RFC 6455.
    /// </remarks>
    internal enum Mask
    {
        /// <summary>
        /// Equivalent to numeric value 0. Indicates not masked.
        /// </summary>
        Off = 0x0,
        /// <summary>
        /// Equivalent to numeric value 1. Indicates masked.
        /// </summary>
        On = 0x1
    }
    //=========================================================================================
    //=====================================================================================
    /// <summary>
    /// Indicates the WebSocket frame type.
    /// </summary>
    /// <remarks>
    /// The values of this enumeration are defined in
    /// <see href="http://tools.ietf.org/html/rfc6455#section-5.2">
    /// Section 5.2</see> of RFC 6455.
    /// </remarks>
    internal enum Opcode
    {
        /// <summary>
        /// Equivalent to numeric value 0. Indicates continuation frame.
        /// </summary>
        Cont = 0x0,
        /// <summary>
        /// Equivalent to numeric value 1. Indicates text frame.
        /// </summary>
        Text = 0x1,
        /// <summary>
        /// Equivalent to numeric value 2. Indicates binary frame.
        /// </summary>
        Binary = 0x2,
        /// <summary>
        /// Equivalent to numeric value 8. Indicates connection close frame.
        /// </summary>
        Close = 0x8,
        /// <summary>
        /// Equivalent to numeric value 9. Indicates ping frame.
        /// </summary>
        Ping = 0x9,
        /// <summary>
        /// Equivalent to numeric value 10. Indicates pong frame.
        /// </summary>
        Pong = 0xa
    }
    //=================================================================================
    internal class PayloadData : IEnumerable<byte>
    {
        private byte[] _data;
        private static readonly byte[] _emptyBytes;
        private long _extDataLength;
        private long _length;

        /// <summary>
        /// Represents the empty payload data.
        /// </summary>
        public static readonly PayloadData Empty;

        /// <summary>
        /// Represents the allowable max length of payload data.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   A <see cref="WebSocketException"/> is thrown when the length of
        ///   incoming payload data is greater than the value of this field.
        ///   </para>
        ///   <para>
        ///   If you would like to change the value of this field, it must be
        ///   a number between <see cref="WebSocket.FragmentLength"/> and
        ///   <see cref="Int64.MaxValue"/> inclusive.
        ///   </para>
        /// </remarks>
        public static readonly ulong MaxLength;

        static PayloadData()
        {
            _emptyBytes = new byte[0];

            Empty = new PayloadData(_emptyBytes, 0);
            MaxLength = Int64.MaxValue;
        }

        internal PayloadData(byte[] data)
          : this(data, data.LongLength)
        {
        }

        internal PayloadData(byte[] data, long length)
        {
            _data = data;
            _length = length;
        }

        internal PayloadData(ushort code, string reason)
        {
            _data = code.Append(reason);
            _length = _data.LongLength;
        }

        internal ushort Code
        {
            get
            {
                return _length >= 2
                       ? _data.SubArray(0, 2).ToUInt16(ByteOrder.Big)
                       : (ushort)1005;
            }
        }

        internal long ExtensionDataLength
        {
            get
            {
                return _extDataLength;
            }

            set
            {
                _extDataLength = value;
            }
        }

        internal bool HasReservedCode
        {
            get
            {
                return _length >= 2 && Code.IsReservedStatusCode();
            }
        }

        internal string Reason
        {
            get
            {
                if (_length <= 2)
                    return String.Empty;

                var bytes = _data.SubArray(2, _length - 2);

                string reason;

                return bytes.TryGetUTF8DecodedString(out reason)
                       ? reason
                       : String.Empty;
            }
        }

        public byte[] ApplicationData
        {
            get
            {
                return _extDataLength > 0
                       ? _data.SubArray(_extDataLength, _length - _extDataLength)
                       : _data;
            }
        }

        public byte[] ExtensionData
        {
            get
            {
                return _extDataLength > 0
                       ? _data.SubArray(0, _extDataLength)
                       : _emptyBytes;
            }
        }

        public ulong Length
        {
            get
            {
                return (ulong)_length;
            }
        }

        internal void Mask(byte[] key)
        {
            for (long i = 0; i < _length; i++)
                _data[i] = (byte)(_data[i] ^ key[i % 4]);
        }

        public IEnumerator<byte> GetEnumerator()
        {
            foreach (var b in _data)
                yield return b;
        }

        public byte[] ToArray()
        {
            return _data;
        }

        public override string ToString()
        {
            return BitConverter.ToString(_data);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
    //===============================================================================
    /// <summary>
    /// Indicates whether each RSV (RSV1, RSV2, and RSV3) of a WebSocket
    /// frame is non-zero.
    /// </summary>
    /// <remarks>
    /// The values of this enumeration are defined in
    /// <see href="http://tools.ietf.org/html/rfc6455#section-5.2">
    /// Section 5.2</see> of RFC 6455.
    /// </remarks>
    internal enum Rsv
    {
        /// <summary>
        /// Equivalent to numeric value 0. Indicates zero.
        /// </summary>
        Off = 0x0,
        /// <summary>
        /// Equivalent to numeric value 1. Indicates non-zero.
        /// </summary>
        On = 0x1
    }
    //===============================================================================
    // Реализует интерфейс WebSocket.
    // Этот класс предоставляет набор методов и свойств для двусторонней связи 
    // с использованием протокола WebSocket.
    public class WebSocket : IDisposable
    {
        private AuthenticationChallenge _authChallenge;
        private string _base64Key;
        private Action _closeContext;
        private CompressionMethod _compression;
        private WebSocketContext _context;
        private CookieCollection _cookies;
        private NetworkCredential _credentials;
        private bool _emitOnPing;
        private static readonly byte[] _emptyBytes;
        private bool _enableRedirection;
        private string _extensions;
        private bool _extensionsRequested;
        private object _forMessageEventQueue;
        private object _forPing;
        private object _forSend;
        private object _forState;
        private MemoryStream _fragmentsBuffer;
        private bool _fragmentsCompressed;
        private Opcode _fragmentsOpcode;
        private const string _guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        private Func<WebSocketContext, string> _handshakeRequestChecker;
        private bool _ignoreExtensions;
        private bool _inContinuation;
        private volatile bool _inMessage;
        private bool _isClient;
        private bool _isSecure;
        private volatile Logger _log;
        private static readonly int _maxRetryCountForConnect;
        private Action<MessageEventArgs> _message;
        private Queue<MessageEventArgs> _messageEventQueue;
        private bool _noDelay;
        private uint _nonceCount;
        private string _origin;
        private ManualResetEvent _pongReceived;
        private bool _preAuth;
        private string _protocol;
        private string[] _protocols;
        private bool _protocolsRequested;
        private NetworkCredential _proxyCredentials;
        private Uri _proxyUri;
        private volatile WebSocketState _readyState;
        private ManualResetEvent _receivingExited;
        private int _retryCountForConnect;
        private Socket _socket;
        private ClientSslConfiguration _sslConfig;
        private Stream _stream;
        private TcpClient _tcpClient;
        private Uri _uri;
        private const string _version = "13";
        private TimeSpan _waitTime;

        // Представляет длину, используемую для определения того, должны ли данные 
        // быть фрагментированы при отправке.
        // Данные будут фрагментированы, если его длина больше, чем значение этого поля.
        // Если вы хотите изменить значение, вы должны установить его на значение от 125 до <c> int32.maxvalue - 14 </c> включительно.
        internal static readonly int FragmentLength;

        // Представляет генератор случайных чисел, используемый внутри.
        internal static readonly RandomNumberGenerator RandomNumber;

        static WebSocket()
        {
            _emptyBytes = new byte[0];
            _maxRetryCountForConnect = 10;

            FragmentLength = 1016;
            RandomNumber = new RNGCryptoServiceProvider();
        }

        // Как сервер
        internal WebSocket(HttpListenerWebSocketContext context, string protocol)
        {
            _context = context;
            _protocol = protocol;

            _closeContext = context.Close;
            _isSecure = context.IsSecureConnection;
            _log = context.Log;
            _message = messages;
            _socket = context.Socket;
            _stream = context.Stream;
            _waitTime = TimeSpan.FromSeconds(1);

            init();
        }

        // Как сервер
        internal WebSocket(TcpListenerWebSocketContext context, string protocol)
        {
            _context = context;
            _protocol = protocol;

            _closeContext = context.Close;
            _isSecure = context.IsSecureConnection;
            _log = context.Log;
            _message = messages;
            _socket = context.Socket;
            _stream = context.Stream;
            _waitTime = TimeSpan.FromSeconds(1);

            init();
        }

        // Инициализирует новый экземпляр класса <se See Cref = "WebSocket"/> с указанным 
        // URL и необязательно подпротоколами.
        // <param name="url"> Это <see cref="string"/>  указывает URL, к которому можно подключить.
        // Схема URL должна быть WS или WSS.
        // Новый экземпляр использует безопасное соединение, если схема составляет WSS.
        // <param name="protocols"> Массив <see cref="string"/> который указывает имена подпротоколов, если это необходимо.
        public WebSocket(string url, params string[] protocols)
        {
            if (url == null)
                throw new ArgumentNullException("url");

            if (url.Length == 0)
                throw new ArgumentException("An empty string.", "url");

            string msg;

            if (!url.TryCreateWebSocketUri(out _uri, out msg))
                throw new ArgumentException(msg, "url");

            if (protocols != null && protocols.Length > 0)
            {
                if (!checkProtocols(protocols, out msg))
                    throw new ArgumentException(msg, "protocols");

                _protocols = protocols;
            }

            _base64Key = CreateBase64Key();
            _isClient = true;
            _isSecure = _uri.Scheme == "wss";
            _log = new Logger();
            _message = messagec;
            _retryCountForConnect = -1;
            _waitTime = TimeSpan.FromSeconds(5);

            init();
        }

        internal CookieCollection CookieCollection
        {
            get
            {
                return _cookies;
            }
        }

        // Как сервер
        internal Func<WebSocketContext, string> CustomHandshakeRequestChecker
        {
            get
            {
                return _handshakeRequestChecker;
            }

            set
            {
                _handshakeRequestChecker = value;
            }
        }

        // Как сервер
        internal bool IgnoreExtensions
        {
            get
            {
                return _ignoreExtensions;
            }

            set
            {
                _ignoreExtensions = value;
            }
        }

        // Получает или устанавливает метод сжатия, используемый для сжатия сообщения.
        // Работает, если, если текущее состояние интерфейса является New или Closed.
        // Одно из значений перечисления "CompressionMethod".
        // Указывает метод сжатия, используемый для сжатия сообщения.
        // Значение по умолчанию - "CompressionMethod.None".
        public CompressionMethod Compression
        {
            get
            {
                return _compression;
            }

            set
            {
                if (!_isClient)
                {
                    var msg = "The interface is not for the client.";

                    throw new InvalidOperationException(msg);
                }

                lock (_forState)
                {
                    if (!canSet())
                        return;

                    _compression = value;
                }
            }
        }

        // Получает HTTP cookies, включенные в запрос/ответ рукопожатия.
        // Предоставляет перечислитель, который поддерживает итерацию над коллекцией файлов cookies.
        public IEnumerable<Cookie> Cookies
        {
            get
            {
                lock (_cookies.SyncRoot)
                {
                    foreach (var cookie in _cookies)
                        yield return cookie;
                }
            }
        }

        // Получает учетные данные для аутентификации HTTP (Basic/Digest).
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="NetworkCredential"/> that represents the credentials
        ///   used to authenticate the client.
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        public NetworkCredential Credentials
        {
            get
            {
                return _credentials;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the message event is
        /// emitted when the interface receives a ping.
        /// </summary>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the interface emits the message event when
        ///   receives a ping; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        public bool EmitOnPing
        {
            get
            {
                return _emitOnPing;
            }

            set
            {
                _emitOnPing = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the URL redirection for
        /// the handshake request is allowed.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the interface is
        /// New or Closed.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the interface allows the URL redirection for
        ///   the handshake request; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The set operation is not available if the interface is not for
        /// the client.
        /// </exception>
        public bool EnableRedirection
        {
            get
            {
                return _enableRedirection;
            }

            set
            {
                if (!_isClient)
                {
                    var msg = "The interface is not for the client.";

                    throw new InvalidOperationException(msg);
                }

                lock (_forState)
                {
                    if (!canSet())
                        return;

                    _enableRedirection = value;
                }
            }
        }

        /// <summary>
        /// Gets the extensions selected by the server.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents a list of the extensions
        ///   negotiated between the client and server.
        ///   </para>
        ///   <para>
        ///   An empty string if not specified or selected.
        ///   </para>
        /// </value>
        public string Extensions
        {
            get
            {
                return _extensions ?? String.Empty;
            }
        }

        // Получает значение, указывающее, возможно ли установить связь.
        // true Если связь возможна; В противном случае, false.
        public bool IsAlive
        {
            get
            {
                return ping(_emptyBytes);
            }
        }

        /// <summary>
        /// Gets a value indicating whether the connection is secure.
        /// </summary>
        /// <value>
        /// <c>true</c> if the connection is secure; otherwise, <c>false</c>.
        /// </value>
        public bool IsSecure
        {
            get
            {
                return _isSecure;
            }
        }

        /// <summary>
        /// Gets the logging function.
        /// </summary>
        /// <remarks>
        /// The default logging level is <see cref="LogLevel.Error"/>.
        /// </remarks>
        /// <value>
        /// A <see cref="Logger"/> that provides the logging function.
        /// </value>
        public Logger Log
        {
            get
            {
                return _log;
            }

            internal set
            {
                _log = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the underlying TCP socket
        /// disables a delay when send or receive buffer is not full.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the interface is
        /// New or Closed.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   <c>true</c> if the delay is disabled; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   The default value is <c>false</c>.
        ///   </para>
        /// </value>
        /// <seealso cref="Socket.NoDelay"/>
        public bool NoDelay
        {
            get
            {
                return _noDelay;
            }

            set
            {
                lock (_forState)
                {
                    if (!canSet())
                        return;

                    _noDelay = value;
                }
            }
        }

        /// <summary>
        ///Получает или устанавливает значение Origin заголовка HTTP  для отправки с помощью запроса рукопожатия.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   The HTTP Origin header is defined in
        ///   <see href="http://tools.ietf.org/html/rfc6454#section-7">
        ///   Section 7 of RFC 6454</see>.
        ///   </para>
        ///   <para>
        ///   The interface sends the Origin header if this property has any.
        ///   </para>
        ///   <para>
        ///   The set operation works if the current state of the interface is
        ///   New or Closed.
        ///   </para>
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that represents the value of the Origin
        ///   header to send.
        ///   </para>
        ///   <para>
        ///   The syntax is &lt;scheme&gt;://&lt;host&gt;[:&lt;port&gt;].
        ///   </para>
        ///   <para>
        ///   The default value is <see langword="null"/>.
        ///   </para>
        /// </value>
        /// <exception cref="InvalidOperationException">
        /// The set operation is not available if the interface is not for
        /// the client.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   The value specified for a set operation is not an absolute URI string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The value specified for a set operation includes the path segments.
        ///   </para>
        /// </exception>
        public string Origin
        {
            get
            {
                return _origin;
            }

            set
            {
                if (!_isClient)
                {
                    var msg = "The interface is not for the client.";

                    throw new InvalidOperationException(msg);
                }

                if (!value.IsNullOrEmpty())
                {
                    Uri uri;

                    if (!Uri.TryCreate(value, UriKind.Absolute, out uri))
                    {
                        var msg = "Not an absolute URI string.";

                        throw new ArgumentException(msg, "value");
                    }

                    if (uri.Segments.Length > 1)
                    {
                        var msg = "It includes the path segments.";

                        throw new ArgumentException(msg, "value");
                    }
                }

                lock (_forState)
                {
                    if (!canSet())
                        return;

                    _origin = !value.IsNullOrEmpty() ? value.TrimEnd('/') : value;
                }
            }
        }

        /// <summary>
        /// Gets the name of subprotocol selected by the server.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="string"/> that will be one of the names of
        ///   subprotocols specified by client.
        ///   </para>
        ///   <para>
        ///   An empty string if not specified or selected.
        ///   </para>
        /// </value>
        public string Protocol
        {
            get
            {
                return _protocol ?? String.Empty;
            }

            internal set
            {
                _protocol = value;
            }
        }

        /// <summary>
        /// Gets the current state of the interface.
        /// </summary>
        /// <value>
        ///   <para>
        ///   One of the <see cref="WebSocketState"/> enum values.
        ///   </para>
        ///   <para>
        ///   It indicates the current state of the interface.
        ///   </para>
        ///   <para>
        ///   The default value is <see cref="WebSocketState.New"/>.
        ///   </para>
        /// </value>
        public WebSocketState ReadyState
        {
            get
            {
                return _readyState;
            }
        }

        /// <summary>
        /// Gets the configuration for secure connection.
        /// </summary>
        /// <remarks>
        /// The configuration is used when the interface attempts to connect,
        /// so it must be configured before any connect method is called.
        /// </remarks>
        /// <value>
        /// A <see cref="ClientSslConfiguration"/> that represents the
        /// configuration used to establish a secure connection.
        /// </value>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The interface is not for the client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The interface does not use a secure connection.
        ///   </para>
        /// </exception>
        public ClientSslConfiguration SslConfiguration
        {
            get
            {
                if (!_isClient)
                {
                    var msg = "The interface is not for the client.";

                    throw new InvalidOperationException(msg);
                }

                if (!_isSecure)
                {
                    var msg = "The interface does not use a secure connection.";

                    throw new InvalidOperationException(msg);
                }

                return getSslConfiguration();
            }
        }

        /// <summary>
        /// Gets the URL to which to connect.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="Uri"/> that represents the URL to which to connect.
        ///   </para>
        ///   <para>
        ///   Also it represents the URL requested by the client if the interface
        ///   is for the server.
        ///   </para>
        /// </value>
        public Uri Url
        {
            get
            {
                return _isClient ? _uri : _context.RequestUri;
            }
        }

        /// <summary>
        /// Gets or sets the time to wait for the response to the ping or close.
        /// </summary>
        /// <remarks>
        /// The set operation works if the current state of the interface is
        /// New or Closed.
        /// </remarks>
        /// <value>
        ///   <para>
        ///   A <see cref="TimeSpan"/> that represents the time to wait for
        ///   the response.
        ///   </para>
        ///   <para>
        ///   The default value is the same as 5 seconds if the interface is
        ///   for the client.
        ///   </para>
        /// </value>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The value specified for a set operation is zero or less.
        /// </exception>
        public TimeSpan WaitTime
        {
            get
            {
                return _waitTime;
            }

            set
            {
                if (value <= TimeSpan.Zero)
                {
                    var msg = "Zero or less.";

                    throw new ArgumentOutOfRangeException("value", msg);
                }

                lock (_forState)
                {
                    if (!canSet())
                        return;

                    _waitTime = value;
                }
            }
        }

        /// <summary>
        /// Occurs when the connection has been closed.
        /// </summary>
        public event EventHandler<CloseEventArgs> OnClose;

        /// <summary>
        /// Occurs when the interface gets an error.
        /// </summary>
        public event EventHandler<ErrorEventArgs> OnError;

        /// <summary>
        /// Происходит, когда интерфейс получает сообщение.
        /// </summary>
        public event EventHandler<MessageEventArgs> OnMessage;

        /// <summary>
        /// Происходит, когда соединение было установлено.
        /// </summary>
        public event EventHandler OnOpen;

        private void abort(string reason, Exception exception)
        {
            var code = exception is WebSocketException
                       ? ((WebSocketException)exception).Code
                       : (ushort)1006;

            abort(code, reason);
        }

        private void abort(ushort code, string reason)
        {
            var data = new PayloadData(code, reason);

            close(data, false, false);
        }

        // Как сервер
        private bool accept()
        {
            lock (_forState)
            {
                if (_readyState == WebSocketState.Open)
                {
                    _log.Trace("The connection has already been established.");

                    return false;
                }

                if (_readyState == WebSocketState.Closing)
                {
                    _log.Error("The close process is in progress.");

                    error("An error has occurred before accepting.", null);

                    return false;
                }

                if (_readyState == WebSocketState.Closed)
                {
                    _log.Error("The connection has been closed.");

                    error("An error has occurred before accepting.", null);

                    return false;
                }

                _readyState = WebSocketState.Connecting;

                var accepted = false;

                try
                {
                    accepted = acceptHandshake();
                }
                catch (Exception ex)
                {
                    _log.Fatal(ex.Message);
                    _log.Debug(ex.ToString());

                    abort(1011, "An exception has occurred while accepting.");
                }

                if (!accepted)
                    return false;

                _readyState = WebSocketState.Open;

                return true;
            }
        }

        // Как сервер
        private bool acceptHandshake()
        {
            string msg;

            if (!checkHandshakeRequest(_context, out msg))
            {
                _log.Error(msg);
                _log.Debug(_context.ToString());

                refuseHandshake(1002, "A handshake error has occurred.");

                return false;
            }

            if (!customCheckHandshakeRequest(_context, out msg))
            {
                _log.Error(msg);
                _log.Debug(_context.ToString());

                refuseHandshake(1002, "A handshake error has occurred.");

                return false;
            }

            _base64Key = _context.Headers["Sec-WebSocket-Key"];

            if (_protocol != null)
            {
                var matched = _context
                              .SecWebSocketProtocols
                              .Contains(p => p == _protocol);

                if (!matched)
                    _protocol = null;
            }

            if (!_ignoreExtensions)
            {
                var val = _context.Headers["Sec-WebSocket-Extensions"];

                processSecWebSocketExtensionsClientHeader(val);
            }

            if (_noDelay)
                _socket.NoDelay = true;

            createHandshakeResponse().WriteTo(_stream);

            return true;
        }

        private bool canSet()
        {
            return _readyState == WebSocketState.New
                   || _readyState == WebSocketState.Closed;
        }

        // Как сервер
        private bool checkHandshakeRequest(
          WebSocketContext context, out string message
        )
        {
            message = null;

            if (!context.IsWebSocketRequest)
            {
                message = "Not a WebSocket handshake request.";

                return false;
            }

            var headers = context.Headers;

            var key = headers["Sec-WebSocket-Key"];

            if (key == null)
            {
                message = "The Sec-WebSocket-Key header is non-existent.";

                return false;
            }

            if (key.Length == 0)
            {
                message = "The Sec-WebSocket-Key header is invalid.";

                return false;
            }

            var ver = headers["Sec-WebSocket-Version"];

            if (ver == null)
            {
                message = "The Sec-WebSocket-Version header is non-existent.";

                return false;
            }

            if (ver != _version)
            {
                message = "The Sec-WebSocket-Version header is invalid.";

                return false;
            }

            var subps = headers["Sec-WebSocket-Protocol"];

            if (subps != null)
            {
                if (subps.Length == 0)
                {
                    message = "The Sec-WebSocket-Protocol header is invalid.";

                    return false;
                }
            }

            if (!_ignoreExtensions)
            {
                var exts = headers["Sec-WebSocket-Extensions"];

                if (exts != null)
                {
                    if (exts.Length == 0)
                    {
                        message = "The Sec-WebSocket-Extensions header is invalid.";

                        return false;
                    }
                }
            }

            return true;
        }

        // Как клиент
        private bool checkHandshakeResponse(
          HttpResponse response, out string message
        )
        {
            message = null;

            if (response.IsRedirect)
            {
                message = "The redirection is indicated.";

                return false;
            }

            if (response.IsUnauthorized)
            {
                message = "The authentication is required.";

                return false;
            }

            if (!response.IsWebSocketResponse)
            {
                message = "Not a WebSocket handshake response.";

                return false;
            }

            var headers = response.Headers;

            var key = headers["Sec-WebSocket-Accept"];

            if (key == null)
            {
                message = "The Sec-WebSocket-Accept header is non-existent.";

                return false;
            }

            if (key != CreateResponseKey(_base64Key))
            {
                message = "The Sec-WebSocket-Accept header is invalid.";

                return false;
            }

            var ver = headers["Sec-WebSocket-Version"];

            if (ver != null)
            {
                if (ver != _version)
                {
                    message = "The Sec-WebSocket-Version header is invalid.";

                    return false;
                }
            }

            var subp = headers["Sec-WebSocket-Protocol"];

            if (subp == null)
            {
                if (_protocolsRequested)
                {
                    message = "The Sec-WebSocket-Protocol header is non-existent.";

                    return false;
                }
            }
            else
            {
                var valid = _protocolsRequested
                            && subp.Length > 0
                            && _protocols.Contains(p => p == subp);

                if (!valid)
                {
                    message = "The Sec-WebSocket-Protocol header is invalid.";

                    return false;
                }
            }

            var exts = headers["Sec-WebSocket-Extensions"];

            if (exts != null)
            {
                if (!validateSecWebSocketExtensionsServerHeader(exts))
                {
                    message = "The Sec-WebSocket-Extensions header is invalid.";

                    return false;
                }
            }

            return true;
        }

        private static bool checkProtocols(string[] protocols, out string message)
        {
            message = null;

            Func<string, bool> cond = p => p.IsNullOrEmpty() || !p.IsToken();

            if (protocols.Contains(cond))
            {
                message = "It contains a value that is not a token.";

                return false;
            }

            if (protocols.ContainsTwice())
            {
                message = "It contains a value twice.";

                return false;
            }

            return true;
        }

        // Как клиент
        private bool checkProxyConnectResponse(
          HttpResponse response, out string message
        )
        {
            message = null;

            if (response.IsProxyAuthenticationRequired)
            {
                message = "The proxy authentication is required.";

                return false;
            }

            if (!response.IsSuccess)
            {
                message = "The proxy has failed a connection to the requested URL.";

                return false;
            }

            return true;
        }

        private bool checkReceivedFrame(WebSocketFrame frame, out string message)
        {
            message = null;

            if (frame.IsMasked)
            {
                if (_isClient)
                {
                    message = "A frame from the server is masked.";

                    return false;
                }
            }
            else
            {
                if (!_isClient)
                {
                    message = "A frame from a client is not masked.";

                    return false;
                }
            }

            if (frame.IsCompressed)
            {
                if (_compression == CompressionMethod.None)
                {
                    message = "A frame is compressed without any agreement for it.";

                    return false;
                }

                if (!frame.IsData)
                {
                    message = "A non data frame is compressed.";

                    return false;
                }
            }

            if (frame.IsData)
            {
                if (_inContinuation)
                {
                    message = "A data frame was received while receiving continuation frames.";

                    return false;
                }
            }

            if (frame.IsControl)
            {
                if (frame.Fin == Fin.More)
                {
                    message = "A control frame is fragmented.";

                    return false;
                }

                if (frame.PayloadLength > 125)
                {
                    message = "The payload length of a control frame is greater than 125.";

                    return false;
                }
            }

            if (frame.Rsv2 == Rsv.On)
            {
                message = "The RSV2 of a frame is non-zero without any negotiation for it.";

                return false;
            }

            if (frame.Rsv3 == Rsv.On)
            {
                message = "The RSV3 of a frame is non-zero without any negotiation for it.";

                return false;
            }

            return true;
        }

        private void close(ushort code, string reason)
        {
            if (_readyState == WebSocketState.Closing)
            {
                _log.Trace("The close process is already in progress.");

                return;
            }

            if (_readyState == WebSocketState.Closed)
            {
                _log.Trace("The connection has already been closed.");

                return;
            }

            if (code == 1005)
            {
                close(PayloadData.Empty, true, false);

                return;
            }

            var data = new PayloadData(code, reason);
            var send = !code.IsReservedStatusCode();

            close(data, send, false);
        }

        private void close(PayloadData payloadData, bool send, bool received)
        {
            lock (_forState)
            {
                if (_readyState == WebSocketState.Closing)
                {
                    _log.Trace("The close process is already in progress.");

                    return;
                }

                if (_readyState == WebSocketState.Closed)
                {
                    _log.Trace("The connection has already been closed.");

                    return;
                }

                send = send && _readyState == WebSocketState.Open;

                _readyState = WebSocketState.Closing;
            }

            _log.Trace("Begin closing the connection.");

            var res = closeHandshake(payloadData, send, received);

            releaseResources();

            _log.Trace("End closing the connection.");

            _readyState = WebSocketState.Closed;

            var e = new CloseEventArgs(payloadData, res);

            try
            {
                OnClose.Emit(this, e);
            }
            catch (Exception ex)
            {
                _log.Error(ex.Message);
                _log.Debug(ex.ToString());
            }
        }

        private void closeAsync(ushort code, string reason)
        {
            if (_readyState == WebSocketState.Closing)
            {
                _log.Trace("The close process is already in progress.");

                return;
            }

            if (_readyState == WebSocketState.Closed)
            {
                _log.Trace("The connection has already been closed.");

                return;
            }

            if (code == 1005)
            {
                closeAsync(PayloadData.Empty, true, false);

                return;
            }

            var data = new PayloadData(code, reason);
            var send = !code.IsReservedStatusCode();

            closeAsync(data, send, false);
        }

        private void closeAsync(PayloadData payloadData, bool send, bool received)
        {
            Action<PayloadData, bool, bool> closer = close;

            closer.BeginInvoke(
              payloadData, send, received, ar => closer.EndInvoke(ar), null
            );
        }

        private bool closeHandshake(
          PayloadData payloadData, bool send, bool received
        )
        {
            var sent = false;

            if (send)
            {
                var frame = WebSocketFrame.CreateCloseFrame(payloadData, _isClient);
                var bytes = frame.ToArray();

                sent = sendBytes(bytes);

                if (_isClient)
                    frame.Unmask();
            }

            var wait = !received && sent && _receivingExited != null;

            if (wait)
                received = _receivingExited.WaitOne(_waitTime);

            var ret = sent && received;

            var msg = String.Format(
                        "The closing was clean? {0} (sent: {1} received: {2})",
                        ret,
                        sent,
                        received
                      );

            _log.Debug(msg);

            return ret;
        }

        // Как клиент
        private bool connect()
        {
            if (_readyState == WebSocketState.Connecting)
            {
                _log.Trace("The connect process is in progress.");

                return false;
            }

            lock (_forState)
            {
                if (_readyState == WebSocketState.Open)
                {
                    _log.Trace("The connection has already been established.");

                    return false;
                }

                if (_readyState == WebSocketState.Closing)
                {
                    _log.Error("The close process is in progress.");

                    error("An error has occurred before connecting.", null);

                    return false;
                }

                if (_retryCountForConnect >= _maxRetryCountForConnect)
                {
                    _log.Error("An opportunity for reconnecting has been lost.");

                    error("An error has occurred before connecting.", null);

                    return false;
                }

                _retryCountForConnect++;

                _readyState = WebSocketState.Connecting;

                var done = false;

                try
                {
                    done = doHandshake();
                }
                catch (Exception ex)
                {
                    _log.Fatal(ex.Message);
                    _log.Debug(ex.ToString());

                    abort("An exception has occurred while connecting.", ex);
                }

                if (!done)
                    return false;

                _retryCountForConnect = -1;

                _readyState = WebSocketState.Open;

                return true;
            }
        }

        // Как клиент
        private AuthenticationResponse createAuthenticationResponse()
        {
            if (_credentials == null)
                return null;

            if (_authChallenge != null)
            {
                var ret = new AuthenticationResponse(
                            _authChallenge, _credentials, _nonceCount
                          );

                _nonceCount = ret.NonceCount;

                return ret;
            }

            return _preAuth ? new AuthenticationResponse(_credentials) : null;
        }

        // Как клиент
        private string createExtensions()
        {
            var buff = new StringBuilder(80);

            if (_compression != CompressionMethod.None)
            {
                var str = _compression.ToExtensionString(
                            "server_no_context_takeover", "client_no_context_takeover"
                          );

                buff.AppendFormat("{0}, ", str);
            }

            var len = buff.Length;

            if (len <= 2)
                return null;

            buff.Length = len - 2;

            return buff.ToString();
        }

        // Как сервер
        private HttpResponse createHandshakeFailureResponse()
        {
            var ret = HttpResponse.CreateCloseResponse(HttpStatusCode.BadRequest);

            ret.Headers["Sec-WebSocket-Version"] = _version;

            return ret;
        }

        // Как клиент
        private HttpRequest createHandshakeRequest()
        {
            var ret = HttpRequest.CreateWebSocketHandshakeRequest(_uri);

            var headers = ret.Headers;

            headers["Sec-WebSocket-Key"] = _base64Key;
            headers["Sec-WebSocket-Version"] = _version;

            if (!_origin.IsNullOrEmpty())
                headers["Origin"] = _origin;

            if (_protocols != null)
            {
                headers["Sec-WebSocket-Protocol"] = _protocols.ToString(", ");

                _protocolsRequested = true;
            }

            var exts = createExtensions();

            if (exts != null)
            {
                headers["Sec-WebSocket-Extensions"] = exts;

                _extensionsRequested = true;
            }

            var ares = createAuthenticationResponse();

            if (ares != null)
                headers["Authorization"] = ares.ToString();

            if (_cookies.Count > 0)
                ret.SetCookies(_cookies);

            return ret;
        }

        // Как сервер
        private HttpResponse createHandshakeResponse()
        {
            var ret = HttpResponse.CreateWebSocketHandshakeResponse();

            var headers = ret.Headers;

            headers["Sec-WebSocket-Accept"] = CreateResponseKey(_base64Key);

            if (_protocol != null)
                headers["Sec-WebSocket-Protocol"] = _protocol;

            if (_extensions != null)
                headers["Sec-WebSocket-Extensions"] = _extensions;

            if (_cookies.Count > 0)
                ret.SetCookies(_cookies);

            return ret;
        }

        // Как клиент
        private TcpClient createTcpClient(string hostname, int port)
        {
            var ret = new TcpClient(hostname, port);

            if (_noDelay)
                ret.NoDelay = true;

            return ret;
        }

        // Как сервер
        private bool customCheckHandshakeRequest(
          WebSocketContext context, out string message
        )
        {
            message = null;

            if (_handshakeRequestChecker == null)
                return true;

            message = _handshakeRequestChecker(context);

            return message == null;
        }

        private MessageEventArgs dequeueFromMessageEventQueue()
        {
            lock (_forMessageEventQueue)
            {
                return _messageEventQueue.Count > 0
                       ? _messageEventQueue.Dequeue()
                       : null;
            }
        }

        // Как клиент
        private bool doHandshake()
        {
            setClientStream();

            var res = sendHandshakeRequest();

            string msg;

            if (!checkHandshakeResponse(res, out msg))
            {
                _log.Error(msg);
                _log.Debug(res.ToString());

                abort(1002, "A handshake error has occurred.");

                return false;
            }

            if (_protocolsRequested)
                _protocol = res.Headers["Sec-WebSocket-Protocol"];

            if (_extensionsRequested)
            {
                var exts = res.Headers["Sec-WebSocket-Extensions"];

                if (exts == null)
                    _compression = CompressionMethod.None;
                else
                    _extensions = exts;
            }

            var cookies = res.Cookies;

            if (cookies.Count > 0)
                _cookies.SetOrRemove(cookies);

            return true;
        }

        private void enqueueToMessageEventQueue(MessageEventArgs e)
        {
            lock (_forMessageEventQueue)
                _messageEventQueue.Enqueue(e);
        }

        private void error(string message, Exception exception)
        {
            var e = new ErrorEventArgs(message, exception);

            try
            {
                OnError.Emit(this, e);
            }
            catch (Exception ex)
            {
                _log.Error(ex.Message);
                _log.Debug(ex.ToString());
            }
        }

        private ClientSslConfiguration getSslConfiguration()
        {
            if (_sslConfig == null)
                _sslConfig = new ClientSslConfiguration(_uri.DnsSafeHost);

            return _sslConfig;
        }

        private void init()
        {
            _compression = CompressionMethod.None;
            _cookies = new CookieCollection();
            _forPing = new object();
            _forSend = new object();
            _forState = new object();
            _messageEventQueue = new Queue<MessageEventArgs>();
            _forMessageEventQueue = ((ICollection)_messageEventQueue).SyncRoot;
            _readyState = WebSocketState.New;
        }

        private void message()
        {
            MessageEventArgs e = null;

            lock (_forMessageEventQueue)
            {
                if (_inMessage)
                    return;

                if (_messageEventQueue.Count == 0)
                    return;

                if (_readyState != WebSocketState.Open)
                    return;

                e = _messageEventQueue.Dequeue();

                _inMessage = true;
            }

            _message(e);
        }

        private void messagec(MessageEventArgs e)
        {
            do
            {
                try
                {
                    OnMessage.Emit(this, e);
                }
                catch (Exception ex)
                {
                    _log.Error(ex.Message);
                    _log.Debug(ex.ToString());

                    error("An exception has occurred during an OnMessage event.", ex);
                }

                lock (_forMessageEventQueue)
                {
                    if (_messageEventQueue.Count == 0)
                    {
                        _inMessage = false;

                        break;
                    }

                    if (_readyState != WebSocketState.Open)
                    {
                        _inMessage = false;

                        break;
                    }

                    e = _messageEventQueue.Dequeue();
                }
            }
            while (true);
        }

        private void messages(MessageEventArgs e)
        {
            try
            {
                OnMessage.Emit(this, e);
            }
            catch (Exception ex)
            {
                _log.Error(ex.Message);
                _log.Debug(ex.ToString());

                error("An exception has occurred during an OnMessage event.", ex);
            }

            lock (_forMessageEventQueue)
            {
                if (_messageEventQueue.Count == 0)
                {
                    _inMessage = false;

                    return;
                }

                if (_readyState != WebSocketState.Open)
                {
                    _inMessage = false;

                    return;
                }

                e = _messageEventQueue.Dequeue();
            }

            ThreadPool.QueueUserWorkItem(state => messages(e));
        }

        private void open()
        {
            _inMessage = true;

            startReceiving();

            try
            {
                OnOpen.Emit(this, EventArgs.Empty);
            }
            catch (Exception ex)
            {
                _log.Error(ex.Message);
                _log.Debug(ex.ToString());

                error("An exception has occurred during the OnOpen event.", ex);
            }

            MessageEventArgs e = null;

            lock (_forMessageEventQueue)
            {
                if (_messageEventQueue.Count == 0)
                {
                    _inMessage = false;

                    return;
                }

                if (_readyState != WebSocketState.Open)
                {
                    _inMessage = false;

                    return;
                }

                e = _messageEventQueue.Dequeue();
            }

            _message.BeginInvoke(e, ar => _message.EndInvoke(ar), null);
        }

        private bool ping(byte[] data)
        {
            if (_readyState != WebSocketState.Open)
                return false;

            var received = _pongReceived;

            if (received == null)
                return false;

            lock (_forPing)
            {
                try
                {
                    received.Reset();

                    var sent = send(Fin.Final, Opcode.Ping, data, false);

                    if (!sent)
                        return false;

                    return received.WaitOne(_waitTime);
                }
                catch (ObjectDisposedException)
                {
                    return false;
                }
            }
        }

        private bool processCloseFrame(WebSocketFrame frame)
        {
            var data = frame.PayloadData;
            var send = !data.HasReservedCode;

            close(data, send, true);

            return false;
        }

        private bool processDataFrame(WebSocketFrame frame)
        {
            var e = frame.IsCompressed
                    ? new MessageEventArgs(
                        frame.Opcode,
                        frame.PayloadData.ApplicationData.Decompress(_compression)
                      )
                    : new MessageEventArgs(frame);

            enqueueToMessageEventQueue(e);

            return true;
        }

        private bool processFragmentFrame(WebSocketFrame frame)
        {
            if (!_inContinuation)
            {
                if (frame.IsContinuation)
                    return true;

                _fragmentsOpcode = frame.Opcode;
                _fragmentsCompressed = frame.IsCompressed;
                _fragmentsBuffer = new MemoryStream();
                _inContinuation = true;
            }

            _fragmentsBuffer.WriteBytes(frame.PayloadData.ApplicationData, 1024);

            if (frame.IsFinal)
            {
                using (_fragmentsBuffer)
                {
                    var data = _fragmentsCompressed
                               ? _fragmentsBuffer.DecompressToArray(_compression)
                               : _fragmentsBuffer.ToArray();

                    var e = new MessageEventArgs(_fragmentsOpcode, data);

                    enqueueToMessageEventQueue(e);
                }

                _fragmentsBuffer = null;
                _inContinuation = false;
            }

            return true;
        }

        private bool processPingFrame(WebSocketFrame frame)
        {
            _log.Trace("A ping was received.");

            var pong = WebSocketFrame.CreatePongFrame(frame.PayloadData, _isClient);

            lock (_forState)
            {
                if (_readyState != WebSocketState.Open)
                {
                    _log.Trace("A pong to this ping cannot be sent.");

                    return true;
                }

                var bytes = pong.ToArray();
                var sent = sendBytes(bytes);

                if (!sent)
                    return false;
            }

            _log.Trace("A pong to this ping has been sent.");

            if (_emitOnPing)
            {
                if (_isClient)
                    pong.Unmask();

                var e = new MessageEventArgs(frame);

                enqueueToMessageEventQueue(e);
            }

            return true;
        }

        private bool processPongFrame(WebSocketFrame frame)
        {
            _log.Trace("A pong was received.");

            try
            {
                _pongReceived.Set();
            }
            catch (NullReferenceException)
            {
                return false;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }

            _log.Trace("It has been signaled.");

            return true;
        }

        private bool processReceivedFrame(WebSocketFrame frame)
        {
            string msg;

            if (!checkReceivedFrame(frame, out msg))
            {
                _log.Error(msg);
                _log.Debug(frame.ToString(false));

                abort(1002, "An error has occurred while receiving.");

                return false;
            }

            frame.Unmask();

            return frame.IsFragment
                   ? processFragmentFrame(frame)
                   : frame.IsData
                     ? processDataFrame(frame)
                     : frame.IsPing
                       ? processPingFrame(frame)
                       : frame.IsPong
                         ? processPongFrame(frame)
                         : frame.IsClose
                           ? processCloseFrame(frame)
                           : processUnsupportedFrame(frame);
        }

        // Как сервер
        private void processSecWebSocketExtensionsClientHeader(string value)
        {
            if (value == null)
                return;

            var buff = new StringBuilder(80);

            var comp = false;

            foreach (var elm in value.SplitHeaderValue(','))
            {
                var ext = elm.Trim();

                if (ext.Length == 0)
                    continue;

                if (!comp)
                {
                    if (ext.IsCompressionExtension(CompressionMethod.Deflate))
                    {
                        _compression = CompressionMethod.Deflate;

                        var str = _compression.ToExtensionString(
                                    "client_no_context_takeover",
                                    "server_no_context_takeover"
                                  );

                        buff.AppendFormat("{0}, ", str);

                        comp = true;
                    }
                }
            }

            var len = buff.Length;

            if (len <= 2)
                return;

            buff.Length = len - 2;

            _extensions = buff.ToString();
        }

        private bool processUnsupportedFrame(WebSocketFrame frame)
        {
            _log.Fatal("An unsupported frame was received.");
            _log.Debug(frame.ToString(false));

            abort(1003, "There is no way to handle it.");

            return false;
        }

        // Как сервер
        private void refuseHandshake(ushort code, string reason)
        {
            createHandshakeFailureResponse().WriteTo(_stream);

            abort(code, reason);
        }

        // Как клиент
        private void releaseClientResources()
        {
            if (_stream != null)
            {
                _stream.Dispose();

                _stream = null;
            }

            if (_tcpClient != null)
            {
                _tcpClient.Close();

                _tcpClient = null;
            }
        }

        private void releaseCommonResources()
        {
            if (_fragmentsBuffer != null)
            {
                _fragmentsBuffer.Dispose();

                _fragmentsBuffer = null;
                _inContinuation = false;
            }

            if (_pongReceived != null)
            {
                _pongReceived.Close();

                _pongReceived = null;
            }

            if (_receivingExited != null)
            {
                _receivingExited.Close();

                _receivingExited = null;
            }
        }

        private void releaseResources()
        {
            if (_isClient)
                releaseClientResources();
            else
                releaseServerResources();

            releaseCommonResources();
        }

        // Как сервер
        private void releaseServerResources()
        {
            if (_closeContext != null)
            {
                _closeContext();

                _closeContext = null;
            }

            _stream = null;
            _context = null;
        }

        private bool send(byte[] rawFrame)
        {
            lock (_forState)
            {
                if (_readyState != WebSocketState.Open)
                {
                    _log.Error("The current state of the interface is not Open.");

                    return false;
                }

                return sendBytes(rawFrame);
            }
        }

        private bool send(Opcode opcode, Stream sourceStream)
        {
            lock (_forSend)
            {
                var dataStream = sourceStream;
                var compressed = false;
                var sent = false;

                try
                {
                    if (_compression != CompressionMethod.None)
                    {
                        dataStream = sourceStream.Compress(_compression);
                        compressed = true;
                    }

                    sent = send(opcode, dataStream, compressed);

                    if (!sent)
                        error("A send has failed.", null);
                }
                catch (Exception ex)
                {
                    _log.Error(ex.Message);
                    _log.Debug(ex.ToString());

                    error("An exception has occurred during a send.", ex);
                }
                finally
                {
                    if (compressed)
                        dataStream.Dispose();

                    sourceStream.Dispose();
                }

                return sent;
            }
        }

        private bool send(Opcode opcode, Stream dataStream, bool compressed)
        {
            var len = dataStream.Length;

            if (len == 0)
                return send(Fin.Final, opcode, _emptyBytes, false);

            var quo = len / FragmentLength;
            var rem = (int)(len % FragmentLength);

            byte[] buff = null;

            if (quo == 0)
            {
                buff = new byte[rem];

                return dataStream.Read(buff, 0, rem) == rem
                       && send(Fin.Final, opcode, buff, compressed);
            }

            if (quo == 1 && rem == 0)
            {
                buff = new byte[FragmentLength];

                return dataStream.Read(buff, 0, FragmentLength) == FragmentLength
                       && send(Fin.Final, opcode, buff, compressed);
            }

            /* Send fragments */

            // Begin

            buff = new byte[FragmentLength];

            var sent = dataStream.Read(buff, 0, FragmentLength) == FragmentLength
                       && send(Fin.More, opcode, buff, compressed);

            if (!sent)
                return false;

            // Continue

            var n = rem == 0 ? quo - 2 : quo - 1;

            for (long i = 0; i < n; i++)
            {
                sent = dataStream.Read(buff, 0, FragmentLength) == FragmentLength
                       && send(Fin.More, Opcode.Cont, buff, false);

                if (!sent)
                    return false;
            }

            // End

            if (rem == 0)
                rem = FragmentLength;
            else
                buff = new byte[rem];

            return dataStream.Read(buff, 0, rem) == rem
                   && send(Fin.Final, Opcode.Cont, buff, false);
        }

        private bool send(Fin fin, Opcode opcode, byte[] data, bool compressed)
        {
            var frame = new WebSocketFrame(fin, opcode, data, compressed, _isClient);
            var rawFrame = frame.ToArray();

            return send(rawFrame);
        }

        private void sendAsync(
          Opcode opcode, Stream sourceStream, Action<bool> completed
        )
        {
            Func<Opcode, Stream, bool> sender = send;

            sender.BeginInvoke(
              opcode,
              sourceStream,
              ar => {
                  try
                  {
                      var sent = sender.EndInvoke(ar);

                      if (completed != null)
                          completed(sent);
                  }
                  catch (Exception ex)
                  {
                      _log.Error(ex.Message);
                      _log.Debug(ex.ToString());

                      error(
                  "An exception has occurred during the callback for an async send.",
                  ex
                );
                  }
              },
              null
            );
        }

        private bool sendBytes(byte[] bytes)
        {
            try
            {
                _stream.Write(bytes, 0, bytes.Length);
            }
            catch (Exception ex)
            {
                _log.Error(ex.Message);
                _log.Debug(ex.ToString());

                return false;
            }

            return true;
        }

        // Как клиент
        private HttpResponse sendHandshakeRequest()
        {
            var req = createHandshakeRequest();

            var timeout = 90000;
            var res = req.GetResponse(_stream, timeout);

            if (res.IsUnauthorized)
            {
                var val = res.Headers["WWW-Authenticate"];

                if (val.IsNullOrEmpty())
                {
                    _log.Debug("No authentication challenge is specified.");

                    return res;
                }

                var achal = AuthenticationChallenge.Parse(val);

                if (achal == null)
                {
                    _log.Debug("An invalid authentication challenge is specified.");

                    return res;
                }

                _authChallenge = achal;

                if (_credentials == null)
                    return res;

                var ares = new AuthenticationResponse(
                             _authChallenge, _credentials, _nonceCount
                           );

                _nonceCount = ares.NonceCount;

                req.Headers["Authorization"] = ares.ToString();

                if (res.CloseConnection)
                {
                    releaseClientResources();
                    setClientStream();
                }

                timeout = 15000;
                res = req.GetResponse(_stream, timeout);
            }

            if (res.IsRedirect)
            {
                if (!_enableRedirection)
                    return res;

                var val = res.Headers["Location"];

                if (val.IsNullOrEmpty())
                {
                    _log.Debug("No URL to redirect is located.");

                    return res;
                }

                Uri uri;
                string msg;

                if (!val.TryCreateWebSocketUri(out uri, out msg))
                {
                    _log.Debug("An invalid URL to redirect is located.");

                    return res;
                }

                releaseClientResources();

                _uri = uri;
                _isSecure = uri.Scheme == "wss";

                setClientStream();

                return sendHandshakeRequest();
            }

            return res;
        }

        // Как клиент
        private HttpResponse sendProxyConnectRequest()
        {
            var req = HttpRequest.CreateConnectRequest(_uri);

            var timeout = 90000;
            var res = req.GetResponse(_stream, timeout);

            if (res.IsProxyAuthenticationRequired)
            {
                if (_proxyCredentials == null)
                    return res;

                var val = res.Headers["Proxy-Authenticate"];

                if (val.IsNullOrEmpty())
                {
                    _log.Debug("No proxy authentication challenge is specified.");

                    return res;
                }

                var achal = AuthenticationChallenge.Parse(val);

                if (achal == null)
                {
                    _log.Debug("An invalid proxy authentication challenge is specified.");

                    return res;
                }

                var ares = new AuthenticationResponse(achal, _proxyCredentials, 0);

                req.Headers["Proxy-Authorization"] = ares.ToString();

                if (res.CloseConnection)
                {
                    releaseClientResources();

                    _tcpClient = createTcpClient(_proxyUri.DnsSafeHost, _proxyUri.Port);
                    _stream = _tcpClient.GetStream();
                }

                timeout = 15000;
                res = req.GetResponse(_stream, timeout);
            }

            return res;
        }

        // Как клиент
        private void setClientStream()
        {
            if (_proxyUri != null)
            {
                _tcpClient = createTcpClient(_proxyUri.DnsSafeHost, _proxyUri.Port);
                _stream = _tcpClient.GetStream();

                var res = sendProxyConnectRequest();

                string msg;

                if (!checkProxyConnectResponse(res, out msg))
                    throw new WebSocketException(msg);
            }
            else
            {
                _tcpClient = createTcpClient(_uri.DnsSafeHost, _uri.Port);
                _stream = _tcpClient.GetStream();
            }

            if (_isSecure)
            {
                var conf = getSslConfiguration();
                var host = conf.TargetHost;

                if (host != _uri.DnsSafeHost)
                {
                    var msg = "An invalid host name is specified.";

                    throw new WebSocketException(
                            CloseStatusCode.TlsHandshakeFailure,
                            msg
                          );
                }

                try
                {
                    var sslStream = new SslStream(
                                      _stream,
                                      false,
                                      conf.ServerCertificateValidationCallback,
                                      conf.ClientCertificateSelectionCallback
                                    );

                    sslStream.AuthenticateAsClient(
                      host,
                      conf.ClientCertificates,
                      conf.EnabledSslProtocols,
                      conf.CheckCertificateRevocation
                    );

                    _stream = sslStream;
                }
                catch (Exception ex)
                {
                    throw new WebSocketException(
                            CloseStatusCode.TlsHandshakeFailure,
                            ex
                          );
                }
            }
        }

        private void startReceiving()
        {
            if (_messageEventQueue.Count > 0)
                _messageEventQueue.Clear();

            _pongReceived = new ManualResetEvent(false);
            _receivingExited = new ManualResetEvent(false);

            Action receive = null;
            receive =
              () =>
                WebSocketFrame.ReadFrameAsync(
                  _stream,
                  false,
                  frame => {
                      var cont = processReceivedFrame(frame)
                           && _readyState != WebSocketState.Closed;

                      if (!cont)
                      {
                          var exited = _receivingExited;

                          if (exited != null)
                              exited.Set();

                          return;
                      }

                      receive();

                      if (_inMessage)
                          return;

                      message();
                  },
                  ex => {
                      _log.Fatal(ex.Message);
                      _log.Debug(ex.ToString());

                      abort("An exception has occurred while receiving.", ex);
                  }
                );

            receive();
        }

        // Как клиент
        private bool validateSecWebSocketExtensionsServerHeader(string value)
        {
            if (!_extensionsRequested)
                return false;

            if (value.Length == 0)
                return false;

            var comp = _compression != CompressionMethod.None;

            foreach (var elm in value.SplitHeaderValue(','))
            {
                var ext = elm.Trim();

                if (comp && ext.IsCompressionExtension(_compression))
                {
                    var param1 = "server_no_context_takeover";
                    var param2 = "client_no_context_takeover";

                    if (!ext.Contains(param1))
                    {
                        // The server did not send back "server_no_context_takeover".

                        return false;
                    }

                    var name = _compression.ToExtensionString();
                    var invalid = ext.SplitHeaderValue(';').Contains(
                                    t => {
                                        t = t.Trim();

                                        var valid = t == name
                                          || t == param1
                                          || t == param2;

                                        return !valid;
                                    }
                                  );

                    if (invalid)
                        return false;

                    comp = false;
                }
                else
                {
                    return false;
                }
            }

            return true;
        }

        // Как сервер
        internal void Accept()
        {
            var accepted = accept();

            if (!accepted)
                return;

            open();
        }

        // Как сервер
        internal void AcceptAsync()
        {
            Func<bool> acceptor = accept;

            acceptor.BeginInvoke(
              ar => {
                  var accepted = acceptor.EndInvoke(ar);

                  if (!accepted)
                      return;

                  open();
              },
              null
            );
        }

        // Как сервер
        internal void Close(PayloadData payloadData, byte[] rawFrame)
        {
            lock (_forState)
            {
                if (_readyState == WebSocketState.Closing)
                {
                    _log.Trace("The close process is already in progress.");

                    return;
                }

                if (_readyState == WebSocketState.Closed)
                {
                    _log.Trace("The connection has already been closed.");

                    return;
                }

                _readyState = WebSocketState.Closing;
            }

            _log.Trace("Begin closing the connection.");

            var sent = rawFrame != null && sendBytes(rawFrame);
            var received = sent && _receivingExited != null
                           ? _receivingExited.WaitOne(_waitTime)
                           : false;

            var res = sent && received;

            var msg = String.Format(
                        "The closing was clean? {0} (sent: {1} received: {2})",
                        res,
                        sent,
                        received
                      );

            _log.Debug(msg);

            releaseServerResources();
            releaseCommonResources();

            _log.Trace("End closing the connection.");

            _readyState = WebSocketState.Closed;

            var e = new CloseEventArgs(payloadData, res);

            try
            {
                OnClose.Emit(this, e);
            }
            catch (Exception ex)
            {
                _log.Error(ex.Message);
                _log.Debug(ex.ToString());
            }
        }

        // Как клиент
        internal static string CreateBase64Key()
        {
            var key = new byte[16];

            RandomNumber.GetBytes(key);

            return Convert.ToBase64String(key);
        }

        internal static string CreateResponseKey(string base64Key)
        {
            SHA1 sha1 = new SHA1CryptoServiceProvider();

            var src = base64Key + _guid;
            var bytes = src.GetUTF8EncodedBytes();
            var key = sha1.ComputeHash(bytes);

            return Convert.ToBase64String(key);
        }

        // Как сервер
        internal bool Ping(byte[] rawFrame)
        {
            if (_readyState != WebSocketState.Open)
                return false;

            var received = _pongReceived;

            if (received == null)
                return false;

            lock (_forPing)
            {
                try
                {
                    received.Reset();

                    var sent = send(rawFrame);

                    if (!sent)
                        return false;

                    return received.WaitOne(_waitTime);
                }
                catch (ObjectDisposedException)
                {
                    return false;
                }
            }
        }

        // Как сервер
        internal void Send(
          Opcode opcode, byte[] data, Dictionary<CompressionMethod, byte[]> cache
        )
        {
            lock (_forSend)
            {
                byte[] found;

                if (!cache.TryGetValue(_compression, out found))
                {
                    found = new WebSocketFrame(
                              Fin.Final,
                              opcode,
                              data.Compress(_compression),
                              _compression != CompressionMethod.None,
                              false
                            )
                            .ToArray();

                    cache.Add(_compression, found);
                }

                send(found);
            }
        }

        // Как сервер
        internal void Send(
          Opcode opcode,
          Stream sourceStream,
          Dictionary<CompressionMethod, Stream> cache
        )
        {
            lock (_forSend)
            {
                Stream found;

                if (!cache.TryGetValue(_compression, out found))
                {
                    found = sourceStream.Compress(_compression);

                    cache.Add(_compression, found);
                }
                else
                {
                    found.Position = 0;
                }

                send(opcode, found, _compression != CompressionMethod.None);
            }
        }

        /// <summary>
        /// Closes the connection.
        /// </summary>
        /// <remarks>
        /// This method does nothing if the current state of the interface is
        /// Closing or Closed.
        /// </remarks>
        public void Close()
        {
            close(1005, String.Empty);
        }

        /// <summary>
        /// Closes the connection with the specified status code.
        /// </summary>
        /// <remarks>
        /// This method does nothing if the current state of the interface is
        /// Closing or Closed.
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   A <see cref="ushort"/> that specifies the status code indicating
        ///   the reason for the close.
        ///   </para>
        ///   <para>
        ///   The status codes are defined in
        ///   <see href="http://tools.ietf.org/html/rfc6455#section-7.4">
        ///   Section 7.4</see> of RFC 6455.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is 1011 (server error).
        ///   It cannot be used by a client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is 1010 (mandatory extension).
        ///   It cannot be used by a server.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="code"/> is less than 1000 or greater than 4999.
        /// </exception>
        public void Close(ushort code)
        {
            Close(code, String.Empty);
        }

        /// <summary>
        /// Closes the connection with the specified status code.
        /// </summary>
        /// <remarks>
        /// This method does nothing if the current state of the interface is
        /// Closing or Closed.
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   One of the <see cref="CloseStatusCode"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the status code indicating the reason for the close.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is an undefined enum value.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.ServerError"/>.
        ///   It cannot be used by a client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.MandatoryExtension"/>.
        ///   It cannot be used by a server.
        ///   </para>
        /// </exception>
        public void Close(CloseStatusCode code)
        {
            Close(code, String.Empty);
        }

        /// <summary>
        /// Closes the connection with the specified status code and reason.
        /// </summary>
        /// <remarks>
        /// This method does nothing if the current state of the interface is
        /// Closing or Closed.
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   A <see cref="ushort"/> that specifies the status code indicating
        ///   the reason for the close.
        ///   </para>
        ///   <para>
        ///   The status codes are defined in
        ///   <see href="http://tools.ietf.org/html/rfc6455#section-7.4">
        ///   Section 7.4</see> of RFC 6455.
        ///   </para>
        /// </param>
        /// <param name="reason">
        ///   <para>
        ///   A <see cref="string"/> that specifies the reason for the close.
        ///   </para>
        ///   <para>
        ///   Its size must be 123 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is 1011 (server error).
        ///   It cannot be used by a client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is 1010 (mandatory extension).
        ///   It cannot be used by a server.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is 1005 (no status) and
        ///   <paramref name="reason"/> is specified.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="reason"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <para>
        ///   <paramref name="code"/> is less than 1000 or greater than 4999.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The size of <paramref name="reason"/> is greater than 123 bytes.
        ///   </para>
        /// </exception>
        public void Close(ushort code, string reason)
        {
            if (!code.IsCloseStatusCode())
            {
                var msg = "Less than 1000 or greater than 4999.";

                throw new ArgumentOutOfRangeException("code", msg);
            }

            if (_isClient)
            {
                if (code == 1011)
                {
                    var msg = "1011 cannot be used.";

                    throw new ArgumentException(msg, "code");
                }
            }
            else
            {
                if (code == 1010)
                {
                    var msg = "1010 cannot be used.";

                    throw new ArgumentException(msg, "code");
                }
            }

            if (reason.IsNullOrEmpty())
            {
                close(code, String.Empty);

                return;
            }

            if (code == 1005)
            {
                var msg = "1005 cannot be used.";

                throw new ArgumentException(msg, "code");
            }

            byte[] bytes;

            if (!reason.TryGetUTF8EncodedBytes(out bytes))
            {
                var msg = "It could not be UTF-8-encoded.";

                throw new ArgumentException(msg, "reason");
            }

            if (bytes.Length > 123)
            {
                var msg = "Its size is greater than 123 bytes.";

                throw new ArgumentOutOfRangeException("reason", msg);
            }

            close(code, reason);
        }

        /// <summary>
        /// Closes the connection with the specified status code and reason.
        /// </summary>
        /// <remarks>
        /// This method does nothing if the current state of the interface is
        /// Closing or Closed.
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   One of the <see cref="CloseStatusCode"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the status code indicating the reason for the close.
        ///   </para>
        /// </param>
        /// <param name="reason">
        ///   <para>
        ///   A <see cref="string"/> that specifies the reason for the close.
        ///   </para>
        ///   <para>
        ///   Its size must be 123 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is an undefined enum value.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.ServerError"/>.
        ///   It cannot be used by a client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.MandatoryExtension"/>.
        ///   It cannot be used by a server.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.NoStatus"/> and
        ///   <paramref name="reason"/> is specified.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="reason"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The size of <paramref name="reason"/> is greater than 123 bytes.
        /// </exception>
        public void Close(CloseStatusCode code, string reason)
        {
            if (!code.IsDefined())
            {
                var msg = "An undefined enum value.";

                throw new ArgumentException(msg, "code");
            }

            if (_isClient)
            {
                if (code == CloseStatusCode.ServerError)
                {
                    var msg = "ServerError cannot be used.";

                    throw new ArgumentException(msg, "code");
                }
            }
            else
            {
                if (code == CloseStatusCode.MandatoryExtension)
                {
                    var msg = "MandatoryExtension cannot be used.";

                    throw new ArgumentException(msg, "code");
                }
            }

            if (reason.IsNullOrEmpty())
            {
                close((ushort)code, String.Empty);

                return;
            }

            if (code == CloseStatusCode.NoStatus)
            {
                var msg = "NoStatus cannot be used.";

                throw new ArgumentException(msg, "code");
            }

            byte[] bytes;

            if (!reason.TryGetUTF8EncodedBytes(out bytes))
            {
                var msg = "It could not be UTF-8-encoded.";

                throw new ArgumentException(msg, "reason");
            }

            if (bytes.Length > 123)
            {
                var msg = "Its size is greater than 123 bytes.";

                throw new ArgumentOutOfRangeException("reason", msg);
            }

            close((ushort)code, reason);
        }

        /// <summary>
        /// Closes the connection asynchronously.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method does not wait for the close to be complete.
        ///   </para>
        ///   <para>
        ///   This method does nothing if the current state of the interface is
        ///   Closing or Closed.
        ///   </para>
        /// </remarks>
        public void CloseAsync()
        {
            closeAsync(1005, String.Empty);
        }

        /// <summary>
        /// Closes the connection asynchronously with the specified status code.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method does not wait for the close to be complete.
        ///   </para>
        ///   <para>
        ///   This method does nothing if the current state of the interface is
        ///   Closing or Closed.
        ///   </para>
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   A <see cref="ushort"/> that specifies the status code indicating
        ///   the reason for the close.
        ///   </para>
        ///   <para>
        ///   The status codes are defined in
        ///   <see href="http://tools.ietf.org/html/rfc6455#section-7.4">
        ///   Section 7.4</see> of RFC 6455.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is 1011 (server error).
        ///   It cannot be used by a client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is 1010 (mandatory extension).
        ///   It cannot be used by a server.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="code"/> is less than 1000 or greater than 4999.
        /// </exception>
        public void CloseAsync(ushort code)
        {
            CloseAsync(code, String.Empty);
        }

        /// <summary>
        /// Closes the connection asynchronously with the specified status code.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method does not wait for the close to be complete.
        ///   </para>
        ///   <para>
        ///   This method does nothing if the current state of the interface is
        ///   Closing or Closed.
        ///   </para>
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   One of the <see cref="CloseStatusCode"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the status code indicating the reason for the close.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is an undefined enum value.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.ServerError"/>.
        ///   It cannot be used by a client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.MandatoryExtension"/>.
        ///   It cannot be used by a server.
        ///   </para>
        /// </exception>
        public void CloseAsync(CloseStatusCode code)
        {
            CloseAsync(code, String.Empty);
        }

        /// <summary>
        /// Closes the connection asynchronously with the specified status code and
        /// reason.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method does not wait for the close to be complete.
        ///   </para>
        ///   <para>
        ///   This method does nothing if the current state of the interface is
        ///   Closing or Closed.
        ///   </para>
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   A <see cref="ushort"/> that specifies the status code indicating
        ///   the reason for the close.
        ///   </para>
        ///   <para>
        ///   The status codes are defined in
        ///   <see href="http://tools.ietf.org/html/rfc6455#section-7.4">
        ///   Section 7.4</see> of RFC 6455.
        ///   </para>
        /// </param>
        /// <param name="reason">
        ///   <para>
        ///   A <see cref="string"/> that specifies the reason for the close.
        ///   </para>
        ///   <para>
        ///   Its size must be 123 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is 1011 (server error).
        ///   It cannot be used by a client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is 1010 (mandatory extension).
        ///   It cannot be used by a server.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is 1005 (no status) and
        ///   <paramref name="reason"/> is specified.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="reason"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <para>
        ///   <paramref name="code"/> is less than 1000 or greater than 4999.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The size of <paramref name="reason"/> is greater than 123 bytes.
        ///   </para>
        /// </exception>
        public void CloseAsync(ushort code, string reason)
        {
            if (!code.IsCloseStatusCode())
            {
                var msg = "Less than 1000 or greater than 4999.";

                throw new ArgumentOutOfRangeException("code", msg);
            }

            if (_isClient)
            {
                if (code == 1011)
                {
                    var msg = "1011 cannot be used.";

                    throw new ArgumentException(msg, "code");
                }
            }
            else
            {
                if (code == 1010)
                {
                    var msg = "1010 cannot be used.";

                    throw new ArgumentException(msg, "code");
                }
            }

            if (reason.IsNullOrEmpty())
            {
                closeAsync(code, String.Empty);

                return;
            }

            if (code == 1005)
            {
                var msg = "1005 cannot be used.";

                throw new ArgumentException(msg, "code");
            }

            byte[] bytes;

            if (!reason.TryGetUTF8EncodedBytes(out bytes))
            {
                var msg = "It could not be UTF-8-encoded.";

                throw new ArgumentException(msg, "reason");
            }

            if (bytes.Length > 123)
            {
                var msg = "Its size is greater than 123 bytes.";

                throw new ArgumentOutOfRangeException("reason", msg);
            }

            closeAsync(code, reason);
        }

        /// <summary>
        /// Closes the connection asynchronously with the specified status code and
        /// reason.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method does not wait for the close to be complete.
        ///   </para>
        ///   <para>
        ///   This method does nothing if the current state of the interface is
        ///   Closing or Closed.
        ///   </para>
        /// </remarks>
        /// <param name="code">
        ///   <para>
        ///   One of the <see cref="CloseStatusCode"/> enum values.
        ///   </para>
        ///   <para>
        ///   It specifies the status code indicating the reason for the close.
        ///   </para>
        /// </param>
        /// <param name="reason">
        ///   <para>
        ///   A <see cref="string"/> that specifies the reason for the close.
        ///   </para>
        ///   <para>
        ///   Its size must be 123 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="code"/> is an undefined enum value.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.ServerError"/>.
        ///   It cannot be used by a client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.MandatoryExtension"/>.
        ///   It cannot be used by a server.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="code"/> is <see cref="CloseStatusCode.NoStatus"/> and
        ///   <paramref name="reason"/> is specified.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="reason"/> could not be UTF-8-encoded.
        ///   </para>
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The size of <paramref name="reason"/> is greater than 123 bytes.
        /// </exception>
        public void CloseAsync(CloseStatusCode code, string reason)
        {
            if (!code.IsDefined())
            {
                var msg = "An undefined enum value.";

                throw new ArgumentException(msg, "code");
            }

            if (_isClient)
            {
                if (code == CloseStatusCode.ServerError)
                {
                    var msg = "ServerError cannot be used.";

                    throw new ArgumentException(msg, "code");
                }
            }
            else
            {
                if (code == CloseStatusCode.MandatoryExtension)
                {
                    var msg = "MandatoryExtension cannot be used.";

                    throw new ArgumentException(msg, "code");
                }
            }

            if (reason.IsNullOrEmpty())
            {
                closeAsync((ushort)code, String.Empty);

                return;
            }

            if (code == CloseStatusCode.NoStatus)
            {
                var msg = "NoStatus cannot be used.";

                throw new ArgumentException(msg, "code");
            }

            byte[] bytes;

            if (!reason.TryGetUTF8EncodedBytes(out bytes))
            {
                var msg = "It could not be UTF-8-encoded.";

                throw new ArgumentException(msg, "reason");
            }

            if (bytes.Length > 123)
            {
                var msg = "Its size is greater than 123 bytes.";

                throw new ArgumentOutOfRangeException("reason", msg);
            }

            closeAsync((ushort)code, reason);
        }

        /// <summary>
        /// Establishes a connection.
        /// </summary>
        /// <remarks>
        /// This method does nothing if the current state of the interface is
        /// Connecting or Open.
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The interface is not for the client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   A series of reconnecting has failed.
        ///   </para>
        /// </exception>
        public void Connect()
        {
            if (!_isClient)
            {
                var msg = "The interface is not for the client.";

                throw new InvalidOperationException(msg);
            }

            if (_retryCountForConnect >= _maxRetryCountForConnect)
            {
                var msg = "A series of reconnecting has failed.";

                throw new InvalidOperationException(msg);
            }

            var connected = connect();

            if (!connected)
                return;

            open();
        }

        /// <summary>
        /// Establishes a connection asynchronously.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method does not wait for the connect process to be complete.
        ///   </para>
        ///   <para>
        ///   This method does nothing if the current state of the interface is
        ///   Connecting or Open.
        ///   </para>
        /// </remarks>
        /// <exception cref="InvalidOperationException">
        ///   <para>
        ///   The interface is not for the client.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   A series of reconnecting has failed.
        ///   </para>
        /// </exception>
        public void ConnectAsync()
        {
            if (!_isClient)
            {
                var msg = "The interface is not for the client.";

                throw new InvalidOperationException(msg);
            }

            if (_retryCountForConnect >= _maxRetryCountForConnect)
            {
                var msg = "A series of reconnecting has failed.";

                throw new InvalidOperationException(msg);
            }

            Func<bool> connector = connect;

            connector.BeginInvoke(
              ar => {
                  var connected = connector.EndInvoke(ar);

                  if (!connected)
                      return;

                  open();
              },
              null
            );
        }

        /// <summary>
        /// Sends a ping to the remote endpoint.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the send has successfully done and a pong has been
        /// received within a time; otherwise, <c>false</c>.
        /// </returns>
        public bool Ping()
        {
            return ping(_emptyBytes);
        }

        /// <summary>
        /// Sends a ping with the specified message to the remote endpoint.
        /// </summary>
        /// <returns>
        /// <c>true</c> if the send has successfully done and a pong has been
        /// received within a time; otherwise, <c>false</c>.
        /// </returns>
        /// <param name="message">
        ///   <para>
        ///   A <see cref="string"/> that specifies the message to send.
        ///   </para>
        ///   <para>
        ///   Its size must be 125 bytes or less in UTF-8.
        ///   </para>
        /// </param>
        /// <exception cref="ArgumentException">
        /// <paramref name="message"/> could not be UTF-8-encoded.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// The size of <paramref name="message"/> is greater than 125 bytes.
        /// </exception>
        public bool Ping(string message)
        {
            if (message.IsNullOrEmpty())
                return ping(_emptyBytes);

            byte[] bytes;

            if (!message.TryGetUTF8EncodedBytes(out bytes))
            {
                var msg = "It could not be UTF-8-encoded.";

                throw new ArgumentException(msg, "message");
            }

            if (bytes.Length > 125)
            {
                var msg = "Its size is greater than 125 bytes.";

                throw new ArgumentOutOfRangeException("message", msg);
            }

            return ping(bytes);
        }

        /// <summary>
        /// Sends the specified data to the remote endpoint.
        /// </summary>
        /// <param name="data">
        /// An array of <see cref="byte"/> that specifies the binary data to send.
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The current state of the interface is not Open.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        public void Send(byte[] data)
        {
            if (_readyState != WebSocketState.Open)
            {
                var msg = "The current state of the interface is not Open.";

                throw new InvalidOperationException(msg);
            }

            if (data == null)
                throw new ArgumentNullException("data");

            send(Opcode.Binary, new MemoryStream(data));
        }

        /// <summary>
        /// Sends the specified file to the remote endpoint.
        /// </summary>
        /// <param name="fileInfo">
        ///   <para>
        ///   A <see cref="FileInfo"/> that specifies the file to send.
        ///   </para>
        ///   <para>
        ///   The file is sent as the binary data.
        ///   </para>
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The current state of the interface is not Open.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileInfo"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   The file does not exist.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The file could not be opened.
        ///   </para>
        /// </exception>
        public void Send(FileInfo fileInfo)
        {
            if (_readyState != WebSocketState.Open)
            {
                var msg = "The current state of the interface is not Open.";

                throw new InvalidOperationException(msg);
            }

            if (fileInfo == null)
                throw new ArgumentNullException("fileInfo");

            if (!fileInfo.Exists)
            {
                var msg = "The file does not exist.";

                throw new ArgumentException(msg, "fileInfo");
            }

            FileStream stream;

            if (!fileInfo.TryOpenRead(out stream))
            {
                var msg = "The file could not be opened.";

                throw new ArgumentException(msg, "fileInfo");
            }

            send(Opcode.Binary, stream);
        }

        /// <summary>
        /// Sends the specified data to the remote endpoint.
        /// </summary>
        /// <param name="data">
        /// A <see cref="string"/> that specifies the text data to send.
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The current state of the interface is not Open.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="data"/> could not be UTF-8-encoded.
        /// </exception>
        public void Send(string data)
        {
            if (_readyState != WebSocketState.Open)
            {
                var msg = "The current state of the interface is not Open.";

                throw new InvalidOperationException(msg);
            }

            if (data == null)
                throw new ArgumentNullException("data");

            byte[] bytes;

            if (!data.TryGetUTF8EncodedBytes(out bytes))
            {
                var msg = "It could not be UTF-8-encoded.";

                throw new ArgumentException(msg, "data");
            }

            send(Opcode.Text, new MemoryStream(bytes));
        }

        /// <summary>
        /// Sends the data from the specified stream instance to the remote endpoint.
        /// </summary>
        /// <param name="stream">
        ///   <para>
        ///   A <see cref="Stream"/> instance from which to read the data to send.
        ///   </para>
        ///   <para>
        ///   The data is sent as the binary data.
        ///   </para>
        /// </param>
        /// <param name="length">
        /// An <see cref="int"/> that specifies the number of bytes to send.
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The current state of the interface is not Open.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="stream"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="stream"/> cannot be read.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is less than 1.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   No data could be read from <paramref name="stream"/>.
        ///   </para>
        /// </exception>
        public void Send(Stream stream, int length)
        {
            if (_readyState != WebSocketState.Open)
            {
                var msg = "The current state of the interface is not Open.";

                throw new InvalidOperationException(msg);
            }

            if (stream == null)
                throw new ArgumentNullException("stream");

            if (!stream.CanRead)
            {
                var msg = "It cannot be read.";

                throw new ArgumentException(msg, "stream");
            }

            if (length < 1)
            {
                var msg = "Less than 1.";

                throw new ArgumentException(msg, "length");
            }

            var bytes = stream.ReadBytes(length);
            var len = bytes.Length;

            if (len == 0)
            {
                var msg = "No data could be read from it.";

                throw new ArgumentException(msg, "stream");
            }

            if (len < length)
            {
                var fmt = "Only {0} byte(s) of data could be read from the stream.";
                var msg = String.Format(fmt, len);

                _log.Warn(msg);
            }

            send(Opcode.Binary, new MemoryStream(bytes));
        }

        /// <summary>
        /// Sends the specified data to the remote endpoint asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="data">
        /// An array of <see cref="byte"/> that specifies the binary data to send.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   The delegate invokes the method called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the method is <c>true</c>
        ///   if the send has successfully done; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The current state of the interface is not Open.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        public void SendAsync(byte[] data, Action<bool> completed)
        {
            if (_readyState != WebSocketState.Open)
            {
                var msg = "The current state of the interface is not Open.";

                throw new InvalidOperationException(msg);
            }

            if (data == null)
                throw new ArgumentNullException("data");

            sendAsync(Opcode.Binary, new MemoryStream(data), completed);
        }

        /// <summary>
        /// Sends the specified file to the remote endpoint asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="fileInfo">
        ///   <para>
        ///   A <see cref="FileInfo"/> that specifies the file to send.
        ///   </para>
        ///   <para>
        ///   The file is sent as the binary data.
        ///   </para>
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   The delegate invokes the method called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the method is <c>true</c>
        ///   if the send has successfully done; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The current state of the interface is not Open.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="fileInfo"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   The file does not exist.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The file could not be opened.
        ///   </para>
        /// </exception>
        public void SendAsync(FileInfo fileInfo, Action<bool> completed)
        {
            if (_readyState != WebSocketState.Open)
            {
                var msg = "The current state of the interface is not Open.";

                throw new InvalidOperationException(msg);
            }

            if (fileInfo == null)
                throw new ArgumentNullException("fileInfo");

            if (!fileInfo.Exists)
            {
                var msg = "The file does not exist.";

                throw new ArgumentException(msg, "fileInfo");
            }

            FileStream stream;

            if (!fileInfo.TryOpenRead(out stream))
            {
                var msg = "The file could not be opened.";

                throw new ArgumentException(msg, "fileInfo");
            }

            sendAsync(Opcode.Binary, stream, completed);
        }

        /// <summary>
        /// Sends the specified data to the remote endpoint asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="data">
        /// A <see cref="string"/> that specifies the text data to send.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   The delegate invokes the method called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the method is <c>true</c>
        ///   if the send has successfully done; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The current state of the interface is not Open.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="data"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="data"/> could not be UTF-8-encoded.
        /// </exception>
        public void SendAsync(string data, Action<bool> completed)
        {
            if (_readyState != WebSocketState.Open)
            {
                var msg = "The current state of the interface is not Open.";

                throw new InvalidOperationException(msg);
            }

            if (data == null)
                throw new ArgumentNullException("data");

            byte[] bytes;

            if (!data.TryGetUTF8EncodedBytes(out bytes))
            {
                var msg = "It could not be UTF-8-encoded.";

                throw new ArgumentException(msg, "data");
            }

            sendAsync(Opcode.Text, new MemoryStream(bytes), completed);
        }

        /// <summary>
        /// Sends the data from the specified stream instance to the remote
        /// endpoint asynchronously.
        /// </summary>
        /// <remarks>
        /// This method does not wait for the send to be complete.
        /// </remarks>
        /// <param name="stream">
        ///   <para>
        ///   A <see cref="Stream"/> instance from which to read the data to send.
        ///   </para>
        ///   <para>
        ///   The data is sent as the binary data.
        ///   </para>
        /// </param>
        /// <param name="length">
        /// An <see cref="int"/> that specifies the number of bytes to send.
        /// </param>
        /// <param name="completed">
        ///   <para>
        ///   An <see cref="T:System.Action{bool}"/> delegate.
        ///   </para>
        ///   <para>
        ///   The delegate invokes the method called when the send is complete.
        ///   </para>
        ///   <para>
        ///   The <see cref="bool"/> parameter passed to the method is <c>true</c>
        ///   if the send has successfully done; otherwise, <c>false</c>.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The current state of the interface is not Open.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="stream"/> is <see langword="null"/>.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="stream"/> cannot be read.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="length"/> is less than 1.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   No data could be read from <paramref name="stream"/>.
        ///   </para>
        /// </exception>
        public void SendAsync(Stream stream, int length, Action<bool> completed)
        {
            if (_readyState != WebSocketState.Open)
            {
                var msg = "The current state of the interface is not Open.";

                throw new InvalidOperationException(msg);
            }

            if (stream == null)
                throw new ArgumentNullException("stream");

            if (!stream.CanRead)
            {
                var msg = "It cannot be read.";

                throw new ArgumentException(msg, "stream");
            }

            if (length < 1)
            {
                var msg = "Less than 1.";

                throw new ArgumentException(msg, "length");
            }

            var bytes = stream.ReadBytes(length);
            var len = bytes.Length;

            if (len == 0)
            {
                var msg = "No data could be read from it.";

                throw new ArgumentException(msg, "stream");
            }

            if (len < length)
            {
                var fmt = "Only {0} byte(s) of data could be read from the stream.";
                var msg = String.Format(fmt, len);

                _log.Warn(msg);
            }

            sendAsync(Opcode.Binary, new MemoryStream(bytes), completed);
        }

        /// <summary>
        /// Sets an HTTP cookie to send with the handshake request.
        /// </summary>
        /// <remarks>
        /// This method works if the current state of the interface is
        /// New or Closed.
        /// </remarks>
        /// <param name="cookie">
        /// A <see cref="Cookie"/> that specifies the cookie to send.
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The interface is not for the client.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="cookie"/> is <see langword="null"/>.
        /// </exception>
        public void SetCookie(Cookie cookie)
        {
            if (!_isClient)
            {
                var msg = "The interface is not for the client.";

                throw new InvalidOperationException(msg);
            }

            if (cookie == null)
                throw new ArgumentNullException("cookie");

            lock (_forState)
            {
                if (!canSet())
                    return;

                lock (_cookies.SyncRoot)
                    _cookies.SetOrRemove(cookie);
            }
        }

        /// <summary>
        /// Sets the credentials for the HTTP authentication (Basic/Digest).
        /// </summary>
        /// <remarks>
        /// This method works if the current state of the interface is
        /// New or Closed.
        /// </remarks>
        /// <param name="username">
        ///   <para>
        ///   A <see cref="string"/> that specifies the username associated
        ///   with the credentials.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> or an empty string if initializes
        ///   the credentials.
        ///   </para>
        /// </param>
        /// <param name="password">
        ///   <para>
        ///   A <see cref="string"/> that specifies the password for the
        ///   username associated with the credentials.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> or an empty string if not necessary.
        ///   </para>
        /// </param>
        /// <param name="preAuth">
        /// A <see cref="bool"/>: <c>true</c> if sends the credentials for
        /// the Basic authentication in advance with the first handshake
        /// request; otherwise, <c>false</c>.
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The interface is not for the client.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="username"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="password"/> contains an invalid character.
        ///   </para>
        /// </exception>
        public void SetCredentials(string username, string password, bool preAuth)
        {
            if (!_isClient)
            {
                var msg = "The interface is not for the client.";

                throw new InvalidOperationException(msg);
            }

            if (!username.IsNullOrEmpty())
            {
                if (username.Contains(':') || !username.IsText())
                {
                    var msg = "It contains an invalid character.";

                    throw new ArgumentException(msg, "username");
                }
            }

            if (!password.IsNullOrEmpty())
            {
                if (!password.IsText())
                {
                    var msg = "It contains an invalid character.";

                    throw new ArgumentException(msg, "password");
                }
            }

            lock (_forState)
            {
                if (!canSet())
                    return;

                if (username.IsNullOrEmpty())
                {
                    _credentials = null;
                    _preAuth = false;

                    return;
                }

                _credentials = new NetworkCredential(
                                 username, password, _uri.PathAndQuery
                               );

                _preAuth = preAuth;
            }
        }

        /// <summary>
        /// Sets the URL of the HTTP proxy server through which to connect and
        /// the credentials for the HTTP proxy authentication (Basic/Digest).
        /// </summary>
        /// <remarks>
        /// This method works if the current state of the interface is
        /// New or Closed.
        /// </remarks>
        /// <param name="url">
        ///   <para>
        ///   A <see cref="string"/> that specifies the URL of the proxy
        ///   server through which to connect.
        ///   </para>
        ///   <para>
        ///   The syntax is http://&lt;host&gt;[:&lt;port&gt;].
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> or an empty string if initializes
        ///   the URL and the credentials.
        ///   </para>
        /// </param>
        /// <param name="username">
        ///   <para>
        ///   A <see cref="string"/> that specifies the username associated
        ///   with the credentials.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> or an empty string if the credentials
        ///   are not necessary.
        ///   </para>
        /// </param>
        /// <param name="password">
        ///   <para>
        ///   A <see cref="string"/> that specifies the password for the
        ///   username associated with the credentials.
        ///   </para>
        ///   <para>
        ///   <see langword="null"/> or an empty string if not necessary.
        ///   </para>
        /// </param>
        /// <exception cref="InvalidOperationException">
        /// The interface is not for the client.
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <para>
        ///   <paramref name="url"/> is not an absolute URI string.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   The scheme of <paramref name="url"/> is not http.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="url"/> includes the path segments.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="username"/> contains an invalid character.
        ///   </para>
        ///   <para>
        ///   -or-
        ///   </para>
        ///   <para>
        ///   <paramref name="password"/> contains an invalid character.
        ///   </para>
        /// </exception>
        public void SetProxy(string url, string username, string password)
        {
            if (!_isClient)
            {
                var msg = "The interface is not for the client.";

                throw new InvalidOperationException(msg);
            }

            Uri uri = null;

            if (!url.IsNullOrEmpty())
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out uri))
                {
                    var msg = "Not an absolute URI string.";

                    throw new ArgumentException(msg, "url");
                }

                if (uri.Scheme != "http")
                {
                    var msg = "The scheme part is not http.";

                    throw new ArgumentException(msg, "url");
                }

                if (uri.Segments.Length > 1)
                {
                    var msg = "It includes the path segments.";

                    throw new ArgumentException(msg, "url");
                }
            }

            if (!username.IsNullOrEmpty())
            {
                if (username.Contains(':') || !username.IsText())
                {
                    var msg = "It contains an invalid character.";

                    throw new ArgumentException(msg, "username");
                }
            }

            if (!password.IsNullOrEmpty())
            {
                if (!password.IsText())
                {
                    var msg = "It contains an invalid character.";

                    throw new ArgumentException(msg, "password");
                }
            }

            lock (_forState)
            {
                if (!canSet())
                    return;

                if (url.IsNullOrEmpty())
                {
                    _proxyUri = null;
                    _proxyCredentials = null;

                    return;
                }

                _proxyUri = uri;
                _proxyCredentials = !username.IsNullOrEmpty()
                                    ? new NetworkCredential(
                                        username,
                                        password,
                                        String.Format(
                                          "{0}:{1}", _uri.DnsSafeHost, _uri.Port
                                        )
                                      )
                                    : null;
            }
        }

        /// <summary>
        /// Closes the connection and releases all associated resources.
        /// </summary>
        /// <remarks>
        ///   <para>
        ///   This method closes the connection with close status 1001 (going away).
        ///   </para>
        ///   <para>
        ///   This method does nothing if the current state of the interface is
        ///   Closing or Closed.
        ///   </para>
        /// </remarks>
        void IDisposable.Dispose()
        {
            close(1001, String.Empty);
        }
    }
    //=================================================================================
    /// <summary>
    /// The exception that is thrown when a fatal error occurs in
    /// the WebSocket communication.
    /// </summary>
    public class WebSocketException : Exception
    {
        private ushort _code;

        private WebSocketException(
          ushort code,
          string message,
          Exception innerException
        )
          : base(message ?? code.GetErrorMessage(), innerException)
        {
            _code = code;
        }

        internal WebSocketException()
          : this(CloseStatusCode.Abnormal, null, null)
        {
        }

        internal WebSocketException(Exception innerException)
          : this(CloseStatusCode.Abnormal, null, innerException)
        {
        }

        internal WebSocketException(string message)
          : this(CloseStatusCode.Abnormal, message, null)
        {
        }

        internal WebSocketException(CloseStatusCode code)
          : this(code, null, null)
        {
        }

        internal WebSocketException(string message, Exception innerException)
          : this(CloseStatusCode.Abnormal, message, innerException)
        {
        }

        internal WebSocketException(CloseStatusCode code, Exception innerException)
          : this(code, null, innerException)
        {
        }

        internal WebSocketException(CloseStatusCode code, string message)
          : this(code, message, null)
        {
        }

        internal WebSocketException(
          CloseStatusCode code,
          string message,
          Exception innerException
        )
          : this((ushort)code, message, innerException)
        {
        }

        /// <summary>
        /// Gets the status code indicating the cause of the exception.
        /// </summary>
        /// <value>
        ///   <para>
        ///   A <see cref="ushort"/> that represents the status code indicating
        ///   the cause of the exception.
        ///   </para>
        ///   <para>
        ///   It is one of the status codes for the WebSocket connection close.
        ///   </para>
        /// </value>
        public ushort Code
        {
            get
            {
                return _code;
            }
        }
    }
    //==============================================================================
    internal class WebSocketFrame : IEnumerable<byte>
    {
        private static readonly int _defaultHeaderLength;
        private static readonly int _defaultMaskingKeyLength;
        private static readonly byte[] _emptyBytes;
        private byte[] _extPayloadLength;
        private Fin _fin;
        private Mask _mask;
        private byte[] _maskingKey;
        private Opcode _opcode;
        private PayloadData _payloadData;
        private int _payloadLength;
        private Rsv _rsv1;
        private Rsv _rsv2;
        private Rsv _rsv3;

        static WebSocketFrame()
        {
            _defaultHeaderLength = 2;
            _defaultMaskingKeyLength = 4;
            _emptyBytes = new byte[0];
        }

        private WebSocketFrame()
        {
        }

        internal WebSocketFrame(
          Fin fin,
          Opcode opcode,
          byte[] data,
          bool compressed,
          bool mask
        )
          : this(fin, opcode, new PayloadData(data), compressed, mask)
        {
        }

        internal WebSocketFrame(
          Fin fin,
          Opcode opcode,
          PayloadData payloadData,
          bool compressed,
          bool mask
        )
        {
            _fin = fin;
            _opcode = opcode;

            _rsv1 = compressed ? Rsv.On : Rsv.Off;
            _rsv2 = Rsv.Off;
            _rsv3 = Rsv.Off;

            var len = payloadData.Length;

            if (len < 126)
            {
                _payloadLength = (int)len;
                _extPayloadLength = _emptyBytes;
            }
            else if (len < 0x010000)
            {
                _payloadLength = 126;
                _extPayloadLength = ((ushort)len).ToByteArray(ByteOrder.Big);
            }
            else
            {
                _payloadLength = 127;
                _extPayloadLength = len.ToByteArray(ByteOrder.Big);
            }

            if (mask)
            {
                _mask = Mask.On;
                _maskingKey = createMaskingKey();

                payloadData.Mask(_maskingKey);
            }
            else
            {
                _mask = Mask.Off;
                _maskingKey = _emptyBytes;
            }

            _payloadData = payloadData;
        }

        internal ulong ExactPayloadLength
        {
            get
            {
                return _payloadLength < 126
                       ? (ulong)_payloadLength
                       : _payloadLength == 126
                         ? _extPayloadLength.ToUInt16(ByteOrder.Big)
                         : _extPayloadLength.ToUInt64(ByteOrder.Big);
            }
        }

        internal int ExtendedPayloadLengthWidth
        {
            get
            {
                return _payloadLength < 126
                       ? 0
                       : _payloadLength == 126
                         ? 2
                         : 8;
            }
        }

        public byte[] ExtendedPayloadLength
        {
            get
            {
                return _extPayloadLength;
            }
        }

        public Fin Fin
        {
            get
            {
                return _fin;
            }
        }

        public bool IsBinary
        {
            get
            {
                return _opcode == Opcode.Binary;
            }
        }

        public bool IsClose
        {
            get
            {
                return _opcode == Opcode.Close;
            }
        }

        public bool IsCompressed
        {
            get
            {
                return _rsv1 == Rsv.On;
            }
        }

        public bool IsContinuation
        {
            get
            {
                return _opcode == Opcode.Cont;
            }
        }

        public bool IsControl
        {
            get
            {
                return _opcode >= Opcode.Close;
            }
        }

        public bool IsData
        {
            get
            {
                return _opcode == Opcode.Text || _opcode == Opcode.Binary;
            }
        }

        public bool IsFinal
        {
            get
            {
                return _fin == Fin.Final;
            }
        }

        public bool IsFragment
        {
            get
            {
                return _fin == Fin.More || _opcode == Opcode.Cont;
            }
        }

        public bool IsMasked
        {
            get
            {
                return _mask == Mask.On;
            }
        }

        public bool IsPing
        {
            get
            {
                return _opcode == Opcode.Ping;
            }
        }

        public bool IsPong
        {
            get
            {
                return _opcode == Opcode.Pong;
            }
        }

        public bool IsText
        {
            get
            {
                return _opcode == Opcode.Text;
            }
        }

        public ulong Length
        {
            get
            {
                return (ulong)(
                         _defaultHeaderLength
                         + _extPayloadLength.Length
                         + _maskingKey.Length
                       )
                       + _payloadData.Length;
            }
        }

        public Mask Mask
        {
            get
            {
                return _mask;
            }
        }

        public byte[] MaskingKey
        {
            get
            {
                return _maskingKey;
            }
        }

        public Opcode Opcode
        {
            get
            {
                return _opcode;
            }
        }

        public PayloadData PayloadData
        {
            get
            {
                return _payloadData;
            }
        }

        public int PayloadLength
        {
            get
            {
                return _payloadLength;
            }
        }

        public Rsv Rsv1
        {
            get
            {
                return _rsv1;
            }
        }

        public Rsv Rsv2
        {
            get
            {
                return _rsv2;
            }
        }

        public Rsv Rsv3
        {
            get
            {
                return _rsv3;
            }
        }

        private static byte[] createMaskingKey()
        {
            var key = new byte[_defaultMaskingKeyLength];

            WebSocket.RandomNumber.GetBytes(key);

            return key;
        }

        private static WebSocketFrame processHeader(byte[] header)
        {
            if (header.Length != _defaultHeaderLength)
            {
                var msg = "The header part of a frame could not be read.";

                throw new WebSocketException(msg);
            }

            // FIN
            var fin = (header[0] & 0x80) == 0x80 ? Fin.Final : Fin.More;

            // RSV1
            var rsv1 = (header[0] & 0x40) == 0x40 ? Rsv.On : Rsv.Off;

            // RSV2
            var rsv2 = (header[0] & 0x20) == 0x20 ? Rsv.On : Rsv.Off;

            // RSV3
            var rsv3 = (header[0] & 0x10) == 0x10 ? Rsv.On : Rsv.Off;

            // Opcode
            var opcode = header[0] & 0x0f;

            // MASK
            var mask = (header[1] & 0x80) == 0x80 ? Mask.On : Mask.Off;

            // Payload Length
            var payloadLen = header[1] & 0x7f;

            if (!opcode.IsSupportedOpcode())
            {
                var msg = "The opcode of a frame is not supported.";

                throw new WebSocketException(CloseStatusCode.UnsupportedData, msg);
            }

            var frame = new WebSocketFrame();

            frame._fin = fin;
            frame._rsv1 = rsv1;
            frame._rsv2 = rsv2;
            frame._rsv3 = rsv3;
            frame._opcode = (Opcode)opcode;
            frame._mask = mask;
            frame._payloadLength = payloadLen;

            return frame;
        }

        private static WebSocketFrame readExtendedPayloadLength(
          Stream stream,
          WebSocketFrame frame
        )
        {
            var len = frame.ExtendedPayloadLengthWidth;

            if (len == 0)
            {
                frame._extPayloadLength = _emptyBytes;

                return frame;
            }

            var bytes = stream.ReadBytes(len);

            if (bytes.Length != len)
            {
                var msg = "The extended payload length of a frame could not be read.";

                throw new WebSocketException(msg);
            }

            frame._extPayloadLength = bytes;

            return frame;
        }

        private static void readExtendedPayloadLengthAsync(
          Stream stream,
          WebSocketFrame frame,
          Action<WebSocketFrame> completed,
          Action<Exception> error
        )
        {
            var len = frame.ExtendedPayloadLengthWidth;

            if (len == 0)
            {
                frame._extPayloadLength = _emptyBytes;

                completed(frame);

                return;
            }

            stream.ReadBytesAsync(
              len,
              bytes => {
                  if (bytes.Length != len)
                  {
                      var msg = "The extended payload length of a frame could not be read.";

                      throw new WebSocketException(msg);
                  }

                  frame._extPayloadLength = bytes;

                  completed(frame);
              },
              error
            );
        }

        private static WebSocketFrame readHeader(Stream stream)
        {
            var bytes = stream.ReadBytes(_defaultHeaderLength);

            return processHeader(bytes);
        }

        private static void readHeaderAsync(
          Stream stream,
          Action<WebSocketFrame> completed,
          Action<Exception> error
        )
        {
            stream.ReadBytesAsync(
              _defaultHeaderLength,
              bytes => {
                  var frame = processHeader(bytes);

                  completed(frame);
              },
              error
            );
        }

        private static WebSocketFrame readMaskingKey(
          Stream stream,
          WebSocketFrame frame
        )
        {
            if (!frame.IsMasked)
            {
                frame._maskingKey = _emptyBytes;

                return frame;
            }

            var bytes = stream.ReadBytes(_defaultMaskingKeyLength);

            if (bytes.Length != _defaultMaskingKeyLength)
            {
                var msg = "The masking key of a frame could not be read.";

                throw new WebSocketException(msg);
            }

            frame._maskingKey = bytes;

            return frame;
        }

        private static void readMaskingKeyAsync(
          Stream stream,
          WebSocketFrame frame,
          Action<WebSocketFrame> completed,
          Action<Exception> error
        )
        {
            if (!frame.IsMasked)
            {
                frame._maskingKey = _emptyBytes;

                completed(frame);

                return;
            }

            stream.ReadBytesAsync(
              _defaultMaskingKeyLength,
              bytes => {
                  if (bytes.Length != _defaultMaskingKeyLength)
                  {
                      var msg = "The masking key of a frame could not be read.";

                      throw new WebSocketException(msg);
                  }

                  frame._maskingKey = bytes;

                  completed(frame);
              },
              error
            );
        }

        private static WebSocketFrame readPayloadData(
          Stream stream,
          WebSocketFrame frame
        )
        {
            var exactPayloadLen = frame.ExactPayloadLength;

            if (exactPayloadLen > PayloadData.MaxLength)
            {
                var msg = "The payload data of a frame is too big.";

                throw new WebSocketException(CloseStatusCode.TooBig, msg);
            }

            if (exactPayloadLen == 0)
            {
                frame._payloadData = PayloadData.Empty;

                return frame;
            }

            var len = (long)exactPayloadLen;
            var bytes = frame._payloadLength > 126
                        ? stream.ReadBytes(len, 1024)
                        : stream.ReadBytes((int)len);

            if (bytes.LongLength != len)
            {
                var msg = "The payload data of a frame could not be read.";

                throw new WebSocketException(msg);
            }

            frame._payloadData = new PayloadData(bytes, len);

            return frame;
        }

        private static void readPayloadDataAsync(
          Stream stream,
          WebSocketFrame frame,
          Action<WebSocketFrame> completed,
          Action<Exception> error
        )
        {
            var exactPayloadLen = frame.ExactPayloadLength;

            if (exactPayloadLen > PayloadData.MaxLength)
            {
                var msg = "The payload data of a frame is too big.";

                throw new WebSocketException(CloseStatusCode.TooBig, msg);
            }

            if (exactPayloadLen == 0)
            {
                frame._payloadData = PayloadData.Empty;

                completed(frame);

                return;
            }

            var len = (long)exactPayloadLen;

            Action<byte[]> comp =
              bytes => {
                  if (bytes.LongLength != len)
                  {
                      var msg = "The payload data of a frame could not be read.";

                      throw new WebSocketException(msg);
                  }

                  frame._payloadData = new PayloadData(bytes, len);

                  completed(frame);
              };

            if (frame._payloadLength > 126)
            {
                stream.ReadBytesAsync(len, 1024, comp, error);

                return;
            }

            stream.ReadBytesAsync((int)len, comp, error);
        }

        private string toDumpString()
        {
            var len = Length;
            var cnt = (long)(len / 4);
            var rem = (int)(len % 4);

            string spFmt;
            string cntFmt;

            if (cnt < 10000)
            {
                spFmt = "{0,4}";
                cntFmt = "{0,4}";
            }
            else if (cnt < 0x010000)
            {
                spFmt = "{0,4}";
                cntFmt = "{0,4:X}";
            }
            else if (cnt < 0x0100000000)
            {
                spFmt = "{0,8}";
                cntFmt = "{0,8:X}";
            }
            else
            {
                spFmt = "{0,16}";
                cntFmt = "{0,16:X}";
            }

            var baseFmt = @"{0} 01234567 89ABCDEF 01234567 89ABCDEF
{0}+--------+--------+--------+--------+
";
            var headerFmt = String.Format(baseFmt, spFmt);

            baseFmt = "{0}|{{1,8}} {{2,8}} {{3,8}} {{4,8}}|\n";
            var lineFmt = String.Format(baseFmt, cntFmt);

            baseFmt = "{0}+--------+--------+--------+--------+";
            var footerFmt = String.Format(baseFmt, spFmt);

            var buff = new StringBuilder(64);

            Func<Action<string, string, string, string>> lineWriter =
              () => {
                  long lineCnt = 0;

                  return (arg1, arg2, arg3, arg4) => {
                      buff.AppendFormat(
                  lineFmt,
                  ++lineCnt,
                  arg1,
                  arg2,
                  arg3,
                  arg4
                );
                  };
              };

            var writeLine = lineWriter();
            var bytes = ToArray();

            buff.AppendFormat(headerFmt, String.Empty);

            for (long i = 0; i <= cnt; i++)
            {
                var j = i * 4;

                if (i < cnt)
                {
                    var arg1 = Convert.ToString(bytes[j], 2).PadLeft(8, '0');
                    var arg2 = Convert.ToString(bytes[j + 1], 2).PadLeft(8, '0');
                    var arg3 = Convert.ToString(bytes[j + 2], 2).PadLeft(8, '0');
                    var arg4 = Convert.ToString(bytes[j + 3], 2).PadLeft(8, '0');

                    writeLine(arg1, arg2, arg3, arg4);

                    continue;
                }

                if (rem > 0)
                {
                    var arg1 = Convert.ToString(bytes[j], 2).PadLeft(8, '0');
                    var arg2 = rem >= 2
                               ? Convert.ToString(bytes[j + 1], 2).PadLeft(8, '0')
                               : String.Empty;

                    var arg3 = rem == 3
                               ? Convert.ToString(bytes[j + 2], 2).PadLeft(8, '0')
                               : String.Empty;

                    writeLine(arg1, arg2, arg3, String.Empty);
                }
            }

            buff.AppendFormat(footerFmt, String.Empty);

            return buff.ToString();
        }

        private string toString()
        {
            var extPayloadLen = _payloadLength >= 126
                                ? ExactPayloadLength.ToString()
                                : String.Empty;

            var maskingKey = _mask == Mask.On
                             ? BitConverter.ToString(_maskingKey)
                             : String.Empty;

            var payloadData = _payloadLength >= 126
                              ? "***"
                              : _payloadLength > 0
                                ? _payloadData.ToString()
                                : String.Empty;

            var fmt = @"                    FIN: {0}
                   RSV1: {1}
                   RSV2: {2}
                   RSV3: {3}
                 Opcode: {4}
                   MASK: {5}
         Payload Length: {6}
Extended Payload Length: {7}
            Masking Key: {8}
           Payload Data: {9}";

            return String.Format(
                     fmt,
                     _fin,
                     _rsv1,
                     _rsv2,
                     _rsv3,
                     _opcode,
                     _mask,
                     _payloadLength,
                     extPayloadLen,
                     maskingKey,
                     payloadData
                   );
        }

        internal static WebSocketFrame CreateCloseFrame(
          PayloadData payloadData,
          bool mask
        )
        {
            return new WebSocketFrame(
                     Fin.Final,
                     Opcode.Close,
                     payloadData,
                     false,
                     mask
                   );
        }

        internal static WebSocketFrame CreatePingFrame(bool mask)
        {
            return new WebSocketFrame(
                     Fin.Final,
                     Opcode.Ping,
                     PayloadData.Empty,
                     false,
                     mask
                   );
        }

        internal static WebSocketFrame CreatePingFrame(byte[] data, bool mask)
        {
            return new WebSocketFrame(
                     Fin.Final,
                     Opcode.Ping,
                     new PayloadData(data),
                     false,
                     mask
                   );
        }

        internal static WebSocketFrame CreatePongFrame(
          PayloadData payloadData,
          bool mask
        )
        {
            return new WebSocketFrame(
                     Fin.Final,
                     Opcode.Pong,
                     payloadData,
                     false,
                     mask
                   );
        }

        internal static WebSocketFrame ReadFrame(Stream stream, bool unmask)
        {
            var frame = readHeader(stream);

            readExtendedPayloadLength(stream, frame);
            readMaskingKey(stream, frame);
            readPayloadData(stream, frame);

            if (unmask)
                frame.Unmask();

            return frame;
        }

        internal static void ReadFrameAsync(
          Stream stream,
          bool unmask,
          Action<WebSocketFrame> completed,
          Action<Exception> error
        )
        {
            readHeaderAsync(
              stream,
              frame =>
                readExtendedPayloadLengthAsync(
                  stream,
                  frame,
                  frame1 =>
                    readMaskingKeyAsync(
                      stream,
                      frame1,
                      frame2 =>
                        readPayloadDataAsync(
                          stream,
                          frame2,
                          frame3 => {
                              if (unmask)
                                  frame3.Unmask();

                              completed(frame3);
                          },
                          error
                        ),
                      error
                    ),
                  error
                ),
              error
            );
        }

        internal string ToString(bool dump)
        {
            return dump ? toDumpString() : toString();
        }

        internal void Unmask()
        {
            if (_mask == Mask.Off)
                return;

            _payloadData.Mask(_maskingKey);

            _maskingKey = _emptyBytes;
            _mask = Mask.Off;
        }

        public IEnumerator<byte> GetEnumerator()
        {
            foreach (var b in ToArray())
                yield return b;
        }

        public byte[] ToArray()
        {
            using (var buff = new MemoryStream())
            {
                var header = (int)_fin;

                header = (header << 1) + (int)_rsv1;
                header = (header << 1) + (int)_rsv2;
                header = (header << 1) + (int)_rsv3;
                header = (header << 4) + (int)_opcode;
                header = (header << 1) + (int)_mask;
                header = (header << 7) + _payloadLength;

                var headerAsUInt16 = (ushort)header;
                var headerAsBytes = headerAsUInt16.ToByteArray(ByteOrder.Big);

                buff.Write(headerAsBytes, 0, _defaultHeaderLength);

                if (_payloadLength >= 126)
                    buff.Write(_extPayloadLength, 0, _extPayloadLength.Length);

                if (_mask == Mask.On)
                    buff.Write(_maskingKey, 0, _defaultMaskingKeyLength);

                if (_payloadLength > 0)
                {
                    var bytes = _payloadData.ToArray();

                    if (_payloadLength > 126)
                        buff.WriteBytes(bytes, 1024);
                    else
                        buff.Write(bytes, 0, bytes.Length);
                }

                buff.Close();

                return buff.ToArray();
            }
        }

        public override string ToString()
        {
            var val = ToArray();

            return BitConverter.ToString(val);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
    //========================================================================
    /// <summary>
    /// Indicates the state of the WebSocket interface.
    /// </summary>
    public enum WebSocketState : ushort
    {
        /// <summary>
        /// Equivalent to numeric value 0. Indicates that a new interface has
        /// been created.
        /// </summary>
        New = 0,
        /// <summary>
        /// Equivalent to numeric value 1. Indicates that the connect process is
        /// in progress.
        /// </summary>
        Connecting = 1,
        /// <summary>
        /// Equivalent to numeric value 2. Indicates that the connection has
        /// been established and the communication is possible.
        /// </summary>
        Open = 2,
        /// <summary>
        /// Equivalent to numeric value 3. Indicates that the close process is
        /// in progress.
        /// </summary>
        Closing = 3,
        /// <summary>
        /// Equivalent to numeric value 4. Indicates that the connection has
        /// been closed or could not be established.
        /// </summary>
        Closed = 4
    }
    //==================================================================================


















}
